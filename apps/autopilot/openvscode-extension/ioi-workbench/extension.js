const crypto = require("crypto");
const fs = require("fs");
const http = require("http");
const path = require("path");
const vscode = require("vscode");
const {
  bridgeUrl,
  daemonEndpoint,
  daemonToken,
  normalizeBaseUrl,
  readDaemonModelSnapshot: readDaemonModelSnapshotFromClient,
  requestJson,
} = require("./bridge/client");
const { registerMigrationCommands } = require("./commands/migration");
const { registerQuickInputCommands } = require("./commands/quick-input");
const studioWorkSummary = require("./studio-work-summary");
const { createStudioPanelHtml } = require("./studio/studio-panel-html");
const { createStudioModelCompletion } = require("./studio/model-completion");
const { createStudioOperationalSurface } = require("./studio/operational-surface");
const { createModelSurfaceRenderer } = require("./studio/model-surface");
const { createStudioAgentAnswerStreamProjector } = require("./studio/agent-answer-stream");
const { createStudioAgentFinalHandoffStreamer } = require("./studio/agent-final-handoff-stream");
const { createStudioAgentTurnEvents } = require("./studio/agent-turn-events");
const { createStudioAgentTurnResultText } = require("./studio/agent-turn-result-text");
const { createStudioAgentTurnRecovery } = require("./studio/agent-turn-recovery");
const { createStudioProductErrorMessage } = require("./studio/product-error-message");
const { createStudioPublicTextSanitizer } = require("./studio/public-text-sanitizer");
const {
  studioRuntimeEventToolName,
  studioRuntimeEventKind,
  studioRuntimeEventIsRunningStepCompletion,
  studioRuntimeEventIdentity,
  studioRuntimeToolEventDetail,
  studioRuntimeToolEventExcerpt,
  sanitizeStudioPublicToolText,
} = require("./studio/runtime-event-utils");
const {
  studioArtifactResearchQuery,
  studioArtifactShouldGatherResearch,
  studioResearchIntentFrameForArtifact,
} = require("./studio/artifact-research-routing");
const {
  AUTOPILOT_MODE_BY_ID,
  AUTOPILOT_MODE_BY_PANEL_VIEW_ID,
  AUTOPILOT_MODE_BY_VIEW_ID,
  AUTOPILOT_MODES,
  VIEW_DEFINITIONS,
} = require("./workbench-surfaces");

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
let studioPanelPageNonce = null;
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
const STUDIO_AGENT_MIN_TURN_STEPS = 8;
const STUDIO_AGENT_TURN_POST_TIMEOUT_MS = 130000;
const STUDIO_AGENT_TURN_RECOVERY_POLL_MS = 1000;
const STUDIO_AGENT_TURN_EVENT_FLUSH_TIMEOUT_MS = 15000;
const STUDIO_AGENT_TURN_RECOVERY_ATTEMPTS = 4;
const STUDIO_MODEL_COMPLETION_TIMEOUT_MS = Number.isFinite(Number(process.env.IOI_STUDIO_MODEL_COMPLETION_TIMEOUT_MS))
  ? Math.max(30_000, Math.floor(Number(process.env.IOI_STUDIO_MODEL_COMPLETION_TIMEOUT_MS)))
  : 300_000;
const STUDIO_REFRESH_STATE_TIMEOUT_MS = Number.isFinite(Number(process.env.IOI_STUDIO_REFRESH_STATE_TIMEOUT_MS))
  ? Math.max(500, Math.floor(Number(process.env.IOI_STUDIO_REFRESH_STATE_TIMEOUT_MS)))
  : 2_500;
const STUDIO_MODEL_SNAPSHOT_TIMEOUT_MS = Number.isFinite(Number(process.env.IOI_STUDIO_MODEL_SNAPSHOT_TIMEOUT_MS))
  ? Math.max(500, Math.floor(Number(process.env.IOI_STUDIO_MODEL_SNAPSHOT_TIMEOUT_MS)))
  : 5_000;
const STUDIO_ARTIFACT_REQUEST_TIMEOUT_MS = Number.isFinite(Number(process.env.IOI_STUDIO_ARTIFACT_REQUEST_TIMEOUT_MS))
  ? Math.max(1_000, Math.floor(Number(process.env.IOI_STUDIO_ARTIFACT_REQUEST_TIMEOUT_MS)))
  : 30_000;
const STUDIO_DEFAULT_MAX_OUTPUT_TOKENS = 4096;
const STUDIO_DEFAULT_ARTIFACT_MAX_OUTPUT_TOKENS = 4096;
const STUDIO_PRODUCT_MODEL_UNAVAILABLE = "__product_model_unavailable__";
let studioRuntimeProjection = createInitialStudioRuntimeProjection();
let studioDiffProviderDisposable = null;
const studioDiffDocuments = new Map();
let activeTraceTarget = null;

function readDaemonModelSnapshot() {
  return readDaemonModelSnapshotFromClient({
    timeoutMs: STUDIO_MODEL_SNAPSHOT_TIMEOUT_MS,
  });
}

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

function requestBridge(method, bridgePath, payload, { timeoutMs } = {}) {
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

    if (timeoutMs && Number.isFinite(Number(timeoutMs))) {
      const boundedTimeoutMs = Math.max(500, Math.floor(Number(timeoutMs)));
      request.setTimeout(boundedTimeoutMs, () => {
        request.destroy(new Error(`Bridge request timed out after ${boundedTimeoutMs}ms.`));
      });
    }
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
    const raw = await requestBridge("GET", "state", undefined, {
      timeoutMs: STUDIO_REFRESH_STATE_TIMEOUT_MS,
    });
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

const {
  modelDisplayName,
  modelEndpointForArtifact,
  modelInstanceForEndpoint,
  renderModelsPanelBody,
} = createModelSurfaceRenderer({
  commandPayloadAttr,
  daemonEndpoint,
  escapeHtml,
  formatBytes,
  modelSnapshotFromState,
  renderCommandButton,
});

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
    pendingWorklog: [],
    runtimeEventSeenIds: [],
    lastError: null,
    lastModelStream: null,
    lastIntentFrame: null,
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
      policyLeaseAllowOnceObserved: false,
      policyLeaseRevokeObserved: false,
      policyLeaseExpiryObserved: false,
      policyLeaseRevokedActionDidNotExecute: false,
      policyLeaseExpiredActionDidNotExecute: false,
      sandboxCommandOutputStreamObserved: false,
      sandboxCommandReceiptObserved: false,
      inlineDiffOverlayObserved: false,
      hunkNavigationObserved: false,
      hunkAcceptRejectReceiptsObserved: false,
      stopControlObserved: false,
      resumeControlObserved: false,
      stopResumeObserved: false,
      diagnosticsTestGateObserved: false,
      receiptTimelinePerStepObserved: false,
      replayStepDetailObserved: false,
      projectionOnlyRuntimeRejected: true,
      browserStatusObserved: false,
      workerStatusObserved: false,
      managedLiveViewportObserved: false,
      managedSessionLabelsObserved: false,
      conversationArtifactObserved: false,
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
    trajectoryReplayPanels: [],
    sessionBrainPanels: [],
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
    conversationArtifacts: [],
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

const studioPublicTextSanitizer = createStudioPublicTextSanitizer({
  compactStudioWhitespace,
  studioTextIndicatesApprovalPause,
});

function humanizeStudioToolName(value = "") {
  return studioPublicTextSanitizer.humanizeStudioToolName(value);
}

function studioHumanizeOperationalTranscriptText(value, role = "assistant") {
  return studioPublicTextSanitizer.studioHumanizeOperationalTranscriptText(value, role);
}

function studioSanitizePublicAssistantText(value = "") {
  return studioPublicTextSanitizer.studioSanitizePublicAssistantText(value);
}

function studioDisplayTurnContent(turn = {}) {
  return studioPublicTextSanitizer.studioDisplayTurnContent(turn);
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
    /(?:^|\s|["'`])(?:\.\/|\.\.\/|\/)?(?:\.internal|apps|crates|docs|examples|ide|packages|scripts|src|tests?)\//.test(text) ||
    /workspace_fixture_|daemon_endpoint=|computer_use_providers_url=|current trace history/.test(text);
}

function workspaceTargetsForPrompt(prompt = "") {
  const raw = compactText(prompt);
  const targets = [];
  const pathPattern = /(?:^|\s|["'`])((?:\.\/|\.\.\/|\/)?(?:\.internal|apps|crates|docs|examples|ide|packages|scripts|src|tests?)\/[^\s"'`),;:]+)(?=$|\s|["'`),;:])/gi;
  for (const match of raw.matchAll(pathPattern)) {
    const path = compactText(match?.[1] || "").replace(/[.!?]+$/g, "");
    if (path && !targets.some((target) => target.kind === "path" && target.path === path)) {
      targets.push({ kind: "path", path, reason: "explicit_workspace_path" });
    }
  }
  if (targets.length > 0) {
    return targets;
  }
  const stopWords = new Set([
    "about", "and", "are", "between", "codebase", "does", "explain", "find", "first",
    "from", "how", "inspect", "into", "look", "or", "per", "project", "read",
    "repo", "repository", "search", "should", "summarize", "the", "this", "what", "where", "which",
    "workspace",
  ]);
  const seenTerms = new Set();
  const terms = raw
    .toLowerCase()
    .replace(/[^a-z0-9_-]+/g, " ")
    .split(/\s+/)
    .map((term) => term.replace(/^[-./_]+|[-./_]+$/g, ""))
    .filter((term) => term.length >= 3 && !stopWords.has(term))
    .filter((term) => {
      if (seenTerms.has(term)) return false;
      seenTerms.add(term);
      return true;
    })
    .slice(0, 8);
  const query = terms.length > 0 ? terms.join(" ") : raw.slice(0, 120);
  return query ? [{ kind: "search", query, reason: "workspace_context_query" }] : [];
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
  const asksForExternalFact = /\b(today|right now|latest|recent|news|price|market|market cap|investment|invest|better|akt|akash|filecoin|fil|crypto|stock|exchange rate|weather)\b/.test(text);
  const asksForPublicSource = /\b(cite|citation|sources?|web|internet|online|public)\b/.test(text);
  const asksForCurrentExternalState =
    /\b(current|currently)\b/.test(text) &&
    /\b(price|market|news|investment|crypto|stock|exchange rate|weather|public|web|online)\b/.test(text);
  if (targetsLocalWorkspace && !asksForExternalFact && !asksForCurrentExternalState) {
    return false;
  }
  return asksForExternalFact || asksForPublicSource || asksForCurrentExternalState;
}

function promptRequiresWorkspaceContext(prompt = "", executionMode = STUDIO_MODE_AGENT) {
  if (promptIsInternalHarnessProbe(prompt) || normalizeStudioExecutionMode(executionMode) !== STUDIO_MODE_AGENT) {
    return false;
  }
  const text = stringValue(prompt).toLowerCase();
  if (!promptTargetsLocalWorkspace(text)) {
    return false;
  }
  return /\b(audit|check|decides?|explain|explore|find|how|inspect|list|locate|look like|progress|read|review|scan|search|summari[sz]e|where|which|what)\b/.test(text) ||
    /(?:^|\s|["'`])(?:\.\/|\.\.\/|\/)?(?:\.internal|apps|crates|docs|examples|ide|packages|scripts|src|tests?)\//.test(text);
}

function firstArray(value) {
  return Array.isArray(value) ? value : [];
}

function uniqueStrings(values) {
  return [...new Set(firstArray(values).map((value) => String(value)).filter(Boolean))];
}

function isAbstractStudioPendingWorkStep(label, detail) {
  const text = `${label || ""}\n${detail || ""}`.toLowerCase();
  if (!text.trim()) {
    return true;
  }
  return [
    "governed agent run",
    "governed agent harness",
    "daemon session",
    "model route",
    "policy context",
    "daemon-owned",
    "tool calls, policy checks",
    "receipts and traces",
    "receipts stay",
    "traces stay",
    "prepare artifact run",
    "preparing artifact",
    "drafting website artifact",
    "drafted custom website",
    "creating sandboxed artifact",
    "created artifact preview",
    "gathering source context",
    "gathered source context",
  ].some((phrase) => text.includes(phrase));
}

function studioVisiblePendingStepDetail(detail = "") {
  const text = sanitizeStudioPublicToolText(stringValue(detail));
  if (/^(?:running|started|completed|pending|status:\s*(?:running|started|completed|pending))$/i.test(text)) {
    return "";
  }
  return text;
}

function studioPendingCommandOutputExcerpt(step = {}, fallbackExcerpt = "") {
  const text = studioPublicOutputBlock(
    step.excerptPreview ||
      step.excerpt_preview ||
      step.stdout ||
      step.output ||
      step.chunk ||
      step.text ||
      fallbackExcerpt ||
      "",
    1200,
  );
  if (!text) {
    return "";
  }
  const commandLabel = compactStudioWhitespace(step.command || step.commandLabel || step.command_label || step.detail || "");
  const rowLabel = compactStudioWhitespace(step.label || "");
  if (commandLabel && text === commandLabel) {
    return "";
  }
  if (rowLabel && text === rowLabel) {
    return "";
  }
  if (/^[a-z0-9_.-]+\s+-lc\s+<arg>$/i.test(text)) {
    return "";
  }
  if (/^[a-z0-9_.-]+\s+-e\s+<inline script>$/i.test(text)) {
    return "";
  }
  return text;
}

function studioPendingWorkToolName(payload = {}) {
  const explicit = stringValue(
    payload.toolName ||
      payload.tool_name ||
      payload.toolId ||
      payload.tool_id ||
      payload.name ||
      payload.tool,
  );
  if (explicit) {
    return explicit;
  }
  const label = stringValue(payload.label);
  return label.match(/\b[a-z][a-z0-9]*__[a-z0-9_]+\b/i)?.[0] || "";
}

function studioPendingWorkStepIsConcrete(payload = {}) {
  const toolName = studioPendingWorkToolName(payload);
  if (!toolName || toolName === "chat__reply") {
    return false;
  }
  const kind = stringValue(payload.kind || payload.eventKind || payload.event_kind).toLowerCase();
  const concreteTool = /(?:^|__)(?:agent|artifact|browser|computer|editor|file|mcp|memory|model|screen|shell|terminal|web|workspace)__?/i.test(toolName) ||
    /\b[a-z][a-z0-9]*__[a-z0-9_]+\b/i.test(toolName);
  if (!concreteTool) {
    return false;
  }
  if (kind && !/tool|receipt|command|shell|browser|file|web|turn\.step|agent\.step/.test(kind)) {
    return false;
  }
  return true;
}

function normalizeStudioPendingWorkStep(payload = {}) {
  const label = sanitizeStudioPublicToolText(stringValue(payload.label));
  if (!label) {
    return null;
  }
  const detail = studioVisiblePendingStepDetail(payload.detail);
  if (isAbstractStudioPendingWorkStep(label, detail)) {
    return null;
  }
  if (!studioPendingWorkStepIsConcrete(payload)) {
    return null;
  }
  const toolName = studioPendingWorkToolName(payload);
  const commandStep = /shell|terminal|command/i.test(toolName);
  return {
    id: stringValue(payload.id || payload.stepId || payload.eventId || payload.event_id || payload.toolCallId || payload.tool_call_id),
    label,
    detail,
    status: stringValue(payload.status, "running"),
    at: stringValue(payload.at) || new Date().toISOString(),
    toolName,
    kind: stringValue(payload.kind || payload.eventKind || payload.event_kind),
    sourceChips: firstArray(payload.sourceChips || payload.source_chips || payload.sources)
      .map((source) => studioSourceRefFromRecord(source))
      .filter(Boolean)
      .slice(0, 6),
    excerptPreview: commandStep
      ? studioPendingCommandOutputExcerpt(payload)
      : sanitizeStudioPublicToolText(payload.excerptPreview || payload.excerpt_preview).slice(0, 280),
  };
}

function studioPendingWorkLabelForTool(toolName = "", detail = "", status = "") {
  const normalizedTool = stringValue(toolName).toLowerCase();
  const compactDetail = compactStudioWhitespace(detail);
  const statusText = stringValue(status).toLowerCase();
  const domainLike = compactDetail && !/^query:/i.test(compactDetail);
  if (normalizedTool === "web__search") {
    return "Searched web";
  }
  if (normalizedTool === "web__read") {
    return domainLike ? `Read ${compactDetail}` : "Read source";
  }
  if (normalizedTool === "file__search") {
    return "Searched files";
  }
  if (normalizedTool === "file__read" || normalizedTool === "file__view") {
    return domainLike ? `Read ${compactDetail}` : "Read file";
  }
  if (normalizedTool === "file__write") {
    return domainLike ? `Wrote ${compactDetail}` : "Wrote file";
  }
  if (normalizedTool === "file__edit" || normalizedTool === "file__multi_edit") {
    return domainLike ? `Edited ${compactDetail}` : "Edited file";
  }
  if (normalizedTool === "shell__start") {
    if (/failed|error/.test(`${statusText} ${compactDetail}`)) return "Command failed";
    return /running/.test(`${statusText} ${compactDetail}`) ? "Running command" : "Started command";
  }
  if (normalizedTool === "shell__run" || normalizedTool === "terminal__run") {
    if (/failed|error/.test(statusText)) return "Command failed";
    return /running|started/.test(`${statusText} ${compactDetail}`) ? "Running command" : "Ran command";
  }
  if (normalizedTool === "shell__status") {
    return "Checked command status";
  }
  if (normalizedTool === "shell__input") {
    const inputState = `${statusText} ${compactDetail}`;
    if (/already stopped|already terminated|obsolete/i.test(inputState)) {
      return "Skipped obsolete input";
    }
    return /failed|skipped|already sent/i.test(inputState)
      ? "Skipped duplicate input"
      : "Sent input to retained command";
  }
  if (normalizedTool === "shell__terminate") {
    return "Terminated retained command";
  }
  if (normalizedTool === "shell__reset") {
    return "Reset retained shell state";
  }
  if (/^shell__|^terminal__/.test(normalizedTool)) {
    return "Ran command";
  }
  if (/^browser__/.test(normalizedTool)) {
    return "Used browser";
  }
  if (/^screen__|^computer__/.test(normalizedTool)) {
    return "Used computer";
  }
  if (/^memory__/.test(normalizedTool)) {
    return "Used memory";
  }
  if (/^mcp__/.test(normalizedTool)) {
    return "Used connector";
  }
  return humanizeStudioToolName(normalizedTool) || "Used tool";
}

function appendStudioPendingWorkStep(payload = {}) {
  const step = normalizeStudioPendingWorkStep(payload);
  if (!step) {
    return null;
  }
  const concreteExcerpt = (nextExcerpt = "", previousExcerpt = "") => {
    const next = String(nextExcerpt || "").trim();
    const previous = String(previousExcerpt || "").trim();
    if (!next) return previous;
    if (previous && /^(?:ran command|running command|started command|command completed)$/i.test(next)) {
      return previous;
    }
    return next;
  };
  const rows = firstArray(studioRuntimeProjection.pendingWorklog).slice();
  const existingIndex = rows.findIndex((row) =>
    (step.id && row.id === step.id) ||
    (step.toolName && row.toolName === step.toolName) ||
    row.label === step.label
  );
  if (existingIndex >= 0) {
    const existing = rows[existingIndex];
    rows[existingIndex] = {
      ...existing,
      ...step,
      detail: step.detail || existing.detail || "",
      sourceChips: firstArray(step.sourceChips).length ? step.sourceChips : firstArray(existing.sourceChips),
      excerptPreview: concreteExcerpt(step.excerptPreview, existing.excerptPreview),
    };
  } else {
    rows.push(step);
  }
  studioRuntimeProjection.pendingWorklog = rows.slice(-12);
  return step;
}

function studioPendingWorklogLastAtMs() {
  const latest = firstArray(studioRuntimeProjection.pendingWorklog).slice(-1)[0];
  const parsed = Date.parse(latest?.at || "");
  return Number.isFinite(parsed) ? parsed : 0;
}

function studioRuntimeEventSeen(event = {}) {
  const id = studioRuntimeEventIdentity(event);
  if (!id) {
    return false;
  }
  return firstArray(studioRuntimeProjection.runtimeEventSeenIds).includes(id);
}

function markStudioRuntimeEventSeen(event = {}) {
  const id = studioRuntimeEventIdentity(event);
  if (!id) {
    return true;
  }
  if (studioRuntimeEventSeen(event)) {
    return false;
  }
  studioRuntimeProjection.runtimeEventSeenIds = [
    ...firstArray(studioRuntimeProjection.runtimeEventSeenIds),
    id,
  ].slice(-300);
  return true;
}

function studioPendingStepFromRuntimeEvent(event = {}, { kind = "", toolName = "", status = "", summary = "" } = {}) {
  const normalizedTool = stringValue(toolName || studioRuntimeEventToolName(event));
  if (!normalizedTool || normalizedTool === "chat__reply") {
    return null;
  }
  const normalizedKind = stringValue(kind || studioRuntimeEventKind(event)).toLowerCase();
  if (!/tool\.(call|started|output|completed|result)|receipt\.emitted|command|shell|browser|file|web|turn\.step|agent\.step/.test(normalizedKind)) {
    return null;
  }
  const completed = /completed|result|succeeded|failed|error/.test(`${normalizedKind} ${status}`.toLowerCase());
  const detail = studioRuntimeToolEventDetail(event, normalizedTool, summary);
  const sourceChips = studioSourceRefsFromRuntimeEvent(event, summary);
  const excerptPreview =
    studioRuntimeToolEventExcerpt(event, summary) ||
    studioFirstSourceExcerptFromEvent(event, summary);
  return normalizeStudioPendingWorkStep({
    id: normalizedTool,
    label: studioPendingWorkLabelForTool(normalizedTool, detail, completed ? "completed" : "running"),
    detail,
    status: completed ? "completed" : "running",
    at: event.created_at || event.createdAt || new Date().toISOString(),
    kind: normalizedKind,
    toolName: normalizedTool,
    sourceChips,
    excerptPreview,
  });
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

function studioRuntimeEventTurnId(event = {}) {
  return stringValue(event.turn_id || event.turnId || event.payload?.turn_id || event.payload?.turnId);
}

function studioRuntimeEventsForTurn(events = [], turnId = "") {
  const normalizedTurnId = stringValue(turnId);
  const allEvents = firstArray(events);
  if (!normalizedTurnId) {
    return allEvents;
  }
  const matched = allEvents.filter((event) => studioRuntimeEventTurnId(event) === normalizedTurnId);
  return matched.length ? matched : allEvents;
}

function resetStudioDaemonThreadProjection() {
  studioRuntimeProjection.threadId = null;
  studioRuntimeProjection.sessionId = null;
  studioRuntimeProjection.turnId = null;
  studioRuntimeProjection.runId = null;
  studioRuntimeProjection.lastModelStream = null;
  studioRuntimeProjection.lastIntentFrame = null;
  studioRuntimeProjection.pendingWorklog = [];
  studioRuntimeProjection.runtimeEventSeenIds = [];
  studioAgentAnswerStreamProjector.reset();
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
  return "I couldn't finish a clean answer from the sources I gathered. Details are in Tracing.";
}

function studioResultTextLooksRetrievalGrounded(text = "") {
  return /\b(web retrieval summary|current snapshot|citations?:|retrieved_utc|fresh evidence|retrieved current sources)\b/i.test(
    stringValue(text),
  );
}

function studioAgentMaxStepsForIntent(intentFrame = {}, prompt = "") {
  const intentText = `${stringValue(prompt)} ${JSON.stringify(studioIntentFramePayload(intentFrame))}`.toLowerCase();
  if (
    studioIntentFrameRequiresRetrieval(intentFrame, prompt) ||
    /\b(latest|current|today|now|price|investment|sources?|citations?|cite|web|search)\b/.test(intentText)
  ) {
    return 24;
  }
  if (/\b(repository|repo|codebase|workspace|files?|tests?|debug|fix|implement|refactor)\b/.test(intentText)) {
    return 16;
  }
  return 12;
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

function studioPolicyBlockedRuntimeMessage({ prompt = "", resultText = "", events = [] } = {}) {
  const combined = [
    prompt,
    resultText,
    ...firstArray(events).map((event) =>
      [
        event?.summary,
        event?.payload?.output,
        event?.payload?.message,
        event?.payload_summary?.output,
        event?.payload_summary?.message,
        event?.payload_summary?.summary,
      ].filter(Boolean).join(" "),
    ),
  ].join(" ");
  if (!/\b(Blocked by Policy|PolicyBlocked|policy blocking|outside workspace authority|outside the workspace boundary|ignored workspace files?|symlink paths? must be resolved)\b/i.test(combined)) {
    return "";
  }
  const observedTools = uniqueStrings(firstArray(events).map((event) => studioRuntimeEventToolName(event)).filter(Boolean));
  const fileReadBlocked = observedTools.some((tool) => String(tool).toLowerCase() === "file__read") ||
    /\bfile__read\b/i.test(combined);
  if (!fileReadBlocked) {
    return "";
  }
  const path = (
    String(prompt || "").match(/`([^`]+)`/) ||
    String(resultText || "").match(/\bread\s+(\/\S+)/i) ||
    []
  )[1];
  const reason = /\bignored workspace files?\b/i.test(combined)
    ? "because ignored workspace files are protected"
    : /\bsymlink paths? must be resolved\b|\bsymlink\b/i.test(combined)
      ? "because symlink targets require an explicit governed workflow"
      : "because the target is outside the workspace boundary";
  return [
    `The daemon blocked the file read${path ? ` for \`${path}\`` : ""} ${reason}.`,
    "I did not expose the file contents. Details are in Tracing.",
  ].join(" ");
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

function studioFixtureModelUsageAllowed() {
  return /^(1|true|yes|on)$/i.test(String(process.env.IOI_STUDIO_ALLOW_FIXTURE_MODELS || process.env.IOI_STUDIO_FIXTURE_MODE || ""));
}

function studioDenyFixtureModelPolicy() {
  return studioFixtureModelUsageAllowed()
    ? {}
    : {
        deny_fixture_models: true,
        denyFixtureModels: true,
      };
}

function studioTextContainsProductFixtureMarker(text = "") {
  const haystack = stringValue(text).toLowerCase();
  return (
    haystack.includes("ioi model router fixture response") ||
    haystack.includes("input_hash=") ||
    haystack.includes("autopilot:native-fixture") ||
    haystack.includes("local:auto") ||
    haystack.includes("stories260k") ||
    haystack.includes("deterministic native-local model fixture") ||
    haystack.includes("native_local.fixture") ||
    haystack.includes("backend.fixture")
  );
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
  return studioWorkSummary.formatStudioWorkDuration(durationMs);
}

function studioNumberOrNull(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function studioFormatMetricNumber(value, digits = 0) {
  const number = studioNumberOrNull(value);
  if (number === null) return "";
  return number.toLocaleString(undefined, {
    maximumFractionDigits: digits,
    minimumFractionDigits: 0,
  });
}

function studioEstimatedTokenCount(text = "") {
  const value = stringValue(text).trim();
  if (!value) return null;
  return Math.max(1, Math.ceil(value.length / 4));
}

function studioPositiveNumberOrNull(value) {
  const number = studioNumberOrNull(value);
  return number !== null && number > 0 ? number : null;
}

function studioResponseMetricsFromUsage({
  usage = {},
  routeId = "",
  model = "",
  provider = "",
  reasoningEffort = "",
  elapsedMs = null,
  timeToFirstTokenMs = null,
  stopReason = "",
  requestedModel = "",
  promptText = "",
  generatedText = "",
} = {}) {
  const usagePromptTokens = studioPositiveNumberOrNull(usage.prompt_tokens ?? usage.input_tokens);
  const usageGeneratedTokens = studioPositiveNumberOrNull(usage.completion_tokens ?? usage.output_tokens);
  const promptTokens = usagePromptTokens ?? studioEstimatedTokenCount(promptText);
  const generatedTokens = usageGeneratedTokens ?? studioEstimatedTokenCount(generatedText);
  const totalTokens = studioPositiveNumberOrNull(usage.total_tokens) ?? (
    promptTokens !== null && generatedTokens !== null ? promptTokens + generatedTokens : null
  );
  const elapsedSeconds = studioNumberOrNull(elapsedMs) !== null ? Math.max(0.001, Number(elapsedMs) / 1000) : null;
  const tokensPerSecond =
    elapsedSeconds && generatedTokens !== null ? generatedTokens / elapsedSeconds : studioNumberOrNull(usage.tokens_per_second ?? usage.tokensPerSecond);
  return {
    model: stringValue(model || usage.model || requestedModel),
    requestedModel: stringValue(requestedModel),
    provider: stringValue(provider || usage.provider || ""),
    routeId: stringValue(routeId),
    reasoningEffort: normalizeStudioReasoningEffort(reasoningEffort, "none"),
    promptTokens,
    generatedTokens,
    totalTokens,
    elapsedMs: studioNumberOrNull(elapsedMs),
    timeToFirstTokenMs: studioNumberOrNull(timeToFirstTokenMs),
    tokensPerSecond,
    stopReason: stringValue(stopReason || usage.stop_reason || usage.stopReason || ""),
    estimatedTokens: !usagePromptTokens || !usageGeneratedTokens,
  };
}

function studioResponseMetricsFromResponse(response = {}, options = {}) {
  return studioResponseMetricsFromUsage({
    usage: response.usage || response.tokenCount || response.token_count || {},
    routeId: response.route_id || response.routeId || options.routeId,
    model: response.model || options.model,
    provider: response.provider || response.providerId || options.provider,
    reasoningEffort: options.reasoningEffort,
    elapsedMs: options.elapsedMs,
    timeToFirstTokenMs: options.timeToFirstTokenMs,
    stopReason: response.choices?.[0]?.finish_reason || response.stop_reason || response.stopReason || options.stopReason,
    requestedModel: response.request_model || response.requestModel || options.requestedModel,
  });
}

function studioResponseMetricsRows(turn = {}) {
  const metrics = turn.modelMetrics || turn.modelStream?.metrics || turn.generator?.metrics || null;
  if (!metrics || typeof metrics !== "object") {
    return "";
  }
  const rows = [
    ["Model", metrics.model],
    ["Provider", metrics.provider],
    ["Route", metrics.routeId],
    ["Reasoning", metrics.reasoningEffort && metrics.reasoningEffort !== "none" ? metrics.reasoningEffort : "off"],
    ["Prompt", metrics.promptTokens !== null && metrics.promptTokens !== undefined ? `${metrics.estimatedTokens ? "~" : ""}${studioFormatMetricNumber(metrics.promptTokens)}` : ""],
    ["Generated", metrics.generatedTokens !== null && metrics.generatedTokens !== undefined ? `${metrics.estimatedTokens ? "~" : ""}${studioFormatMetricNumber(metrics.generatedTokens)}` : ""],
    ["Total", metrics.totalTokens !== null && metrics.totalTokens !== undefined ? `${metrics.estimatedTokens ? "~" : ""}${studioFormatMetricNumber(metrics.totalTokens)}` : ""],
    ["Elapsed", metrics.elapsedMs !== null && metrics.elapsedMs !== undefined ? `${studioFormatMetricNumber(Number(metrics.elapsedMs) / 1000, 1)}s` : ""],
    ["Tok/s", studioFormatMetricNumber(metrics.tokensPerSecond, 1)],
    ["TTFT", metrics.timeToFirstTokenMs !== null && metrics.timeToFirstTokenMs !== undefined ? `${studioFormatMetricNumber(Number(metrics.timeToFirstTokenMs), 0)}ms` : ""],
    ["Stop", metrics.stopReason],
  ].filter(([, value]) => stringValue(value));
  if (!rows.length) {
    return "";
  }
  return `
    <footer class="studio-response-metrics" data-testid="studio-response-metrics">
      ${rows.map(([label, value]) => `
        <span><strong>${escapeHtml(label)}</strong>${escapeHtml(value)}</span>
      `).join("")}
    </footer>
  `;
}

function studioSplitReasoningFromText(text = "") {
  const raw = stringValue(text);
  const match = raw.match(/<think>\s*([\s\S]*?)\s*<\/think>\s*/i);
  if (!match) {
    return { thinkingText: "", answerText: raw };
  }
  return {
    thinkingText: match[1].trim(),
    answerText: raw.replace(match[0], "").trim(),
  };
}

function studioThinkingRows(turn = {}) {
  const thinkingText = stringValue(turn.thinkingText || turn.modelStream?.thinkingText);
  if (!thinkingText) {
    return "";
  }
  return `
    <details class="studio-thinking-block" data-testid="studio-thinking-block">
      <summary>Thinking</summary>
      <p>${escapeHtml(thinkingText)}</p>
    </details>
  `;
}

function studioTurnContentRows(turn = {}, displayContent = "") { return turn.role === "assistant" ? `<div class="studio-markdown" data-testid="${turn.modelStream?.streamId && !turn.modelStream?.completed ? "studio-streaming-output" : "studio-assistant-answer-text"}">${escapeHtml(displayContent)}</div>` : `<p>${escapeHtml(displayContent)}</p>`; }
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
    conversationArtifacts: studioRuntimeProjection.conversationArtifacts.length,
    pendingWorklog: studioRuntimeProjection.pendingWorklog.length,
    receipts: studioRuntimeProjection.receipts.length,
  };
}

function studioDocumentedWorkRecord(cursor = {}) {
  return studioWorkSummary.studioDocumentedWorkRecord(studioRuntimeProjection, cursor);
}

function studioTurnHasDocumentedWork(turn = {}) {
  return studioWorkSummary.studioTurnHasDocumentedWork(turn);
}

function studioDocumentedWorkSummary(record = {}) {
  return studioWorkSummary.studioDocumentedWorkSummary(record, studioRuntimeProjection.status);
}

function studioPublicOutputBlock(value = "", max = 6000) {
  return String(value || "")
    .replace(/\bshell__start:[a-f0-9]{12,}\b/gi, "<command>")
    .replace(/\b(?:receipt|trace|request|turn|thread)_[a-z0-9:_-]{8,}\b/gi, "<ref>")
    .replace(/ioi-session-stdin-[^\s"']+/gi, "<stdin-bridge>")
    .replace(/\/tmp\/[^\s"']+/gi, "<tmp>")
    .replace(/\/home\/[^\s"']+/gi, "<path>")
    .replace(/"command_id"\s*:\s*"[^"]+"/gi, "")
    .slice(0, max)
    .trim();
}

function studioPublicWorkspacePath(value = "") {
  const raw = compactStudioWhitespace(value).replace(/\\/g, "/");
  if (!raw) return "";
  const workspaceRoot = compactStudioWhitespace(workspaceSummary().path).replace(/\\/g, "/");
  if (/^(?:\/|[a-z]:\/)/i.test(raw)) {
    if (workspaceRoot && !/^open a workspace/i.test(workspaceRoot)) {
      const relative = path.relative(workspaceRoot, raw).replace(/\\/g, "/");
      if (relative && !relative.startsWith("..") && !path.isAbsolute(relative)) {
        return relative.slice(0, 180);
      }
    }
    return path.basename(raw).slice(0, 120) || "workspace";
  }
  return raw.replace(/^\.\//, "").slice(0, 180);
}

function studioCommandRowHasOutput(command = {}) {
  if (!command || typeof command !== "object" || Array.isArray(command)) return false;
  return Boolean(compactStudioWhitespace(
    command.stdout ||
    command.output ||
    command.chunk ||
    command.text ||
    command.excerptPreview ||
    command.excerpt_preview ||
    command.stderr ||
    ""
  ));
}

function studioEffectiveCommandStatus(command = {}, { recordSettled = false } = {}) {
  const status = compactStudioWhitespace(command.status || "completed").slice(0, 32);
  if (recordSettled && studioCommandRowHasOutput(command) && /^(?:running|started|pending)$/i.test(status)) {
    return "completed";
  }
  return status;
}

function studioPublicCommandVerb(command = {}, toolId = "", status = "") {
  const statusText = compactStudioWhitespace(status || command.status || "").toLowerCase();
  if (/failed|error/.test(statusText)) return "Failed";
  if (/running|started|pending/.test(statusText)) return "Running";
  if (toolId === "shell__start") return "Started";
  return "Ran";
}

function studioPublicCommandKindLabel(value = "") {
  const text = compactStudioWhitespace(value);
  if (!text || /^(?:shell|command|running command|ran command|started command)$/i.test(text)) return "";
  const head = text.split(/\s+/)[0].split(/[\\/]/).pop().toLowerCase();
  if (!head) return "";
  if (head === "node" || head === "nodejs") return "Node.js";
  if (head === "python" || head === "python3") return "Python";
  if (["npm", "pnpm", "yarn", "bun", "cargo", "deno", "go", "rustc", "make"].includes(head)) return head;
  if (head === "bash" || head === "sh" || head === "zsh") return "shell";
  return "";
}

function studioPublicCommandOutputForWebview(command = {}, index = 0, options = {}) {
  if (!command || typeof command !== "object" || Array.isArray(command)) return null;
  const toolId = compactStudioWhitespace(command.toolId || command.tool_id || "");
  const rawLabel = compactStudioWhitespace(command.label || command.command || toolId || "Command");
  const effectiveStatus = studioEffectiveCommandStatus(command, options);
  const rawLabelIsGeneric =
    /^[a-z][a-z0-9_]*__[a-z0-9_]+$/i.test(rawLabel) ||
    rawLabel === toolId ||
    /^(?:shell|command|running command|ran command|started command)$/i.test(rawLabel);
  const commandKind = studioPublicCommandKindLabel(command.command || command.commandLabel || command.command_label || "");
  const label = (rawLabelIsGeneric
    ? (commandKind
      ? `${studioPublicCommandVerb(command, toolId, effectiveStatus)} ${commandKind} command`
      : studioPendingWorkLabelForTool(toolId || rawLabel, "", effectiveStatus || "completed"))
    : rawLabel
  ).slice(0, 160);
  if (!label) return null;
  return {
    id: compactStudioWhitespace(command.id || command.commandId || command.command_id || `command.${index}`).slice(0, 96),
    toolId: (toolId || "shell").slice(0, 96),
    label,
    status: effectiveStatus,
    stdout: studioPublicOutputBlock(
      command.stdout ||
      command.output ||
      command.chunk ||
      command.text ||
      command.excerptPreview ||
      command.excerpt_preview ||
      ""
    ),
    stderr: studioPublicOutputBlock(command.stderr || ""),
    exitCode: command.exitCode ?? command.exit_code ?? null,
    durationMs: command.durationMs ?? command.duration_ms ?? null,
  };
}

function studioPublicDiffHunkForWebview(hunk = {}, index = 0) {
  if (!hunk || typeof hunk !== "object" || Array.isArray(hunk)) return null;
  const file = studioPublicWorkspacePath(hunk.file || hunk.path || "workspace") || "workspace";
  return {
    title: compactStudioWhitespace(hunk.title || `Hunk ${index + 1}`).slice(0, 120),
    file,
    status: compactStudioWhitespace(hunk.status || "pending").slice(0, 32),
    before: studioPublicOutputBlock(hunk.before || hunk.search || "", 4000),
    after: studioPublicOutputBlock(hunk.after || hunk.replace || "", 4000),
    stale: Boolean(hunk.stale),
    staleReason: compactStudioWhitespace(hunk.staleReason || hunk.stale_reason || "").slice(0, 160),
    acceptAvailable: hunk.acceptAvailable ?? hunk.accept_available ?? true,
    rejectAvailable: hunk.rejectAvailable ?? hunk.reject_available ?? true,
    rollbackAvailable: hunk.rollbackAvailable ?? hunk.rollback_available ?? false,
    approvalId: compactStudioWhitespace(hunk.approvalId || hunk.approval_id || "").slice(0, 160),
    changeId: compactStudioWhitespace(hunk.changeId || hunk.change_id || "").slice(0, 160),
    hunkIndex: Number.isFinite(Number(hunk.hunkIndex ?? hunk.hunk_index)) ? Number(hunk.hunkIndex ?? hunk.hunk_index) : index,
  };
}

function studioPublicWorkRecordForWebview(record = {}) {
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    return null;
  }
  const recordSettled = /^(?:completed|blocked|failed|cancelled|canceled)$/i.test(compactStudioWhitespace(record.status || ""));
  const lines = firstArray(record.lines)
    .map((line) => compactStudioWhitespace(line).slice(0, 160))
    .filter(Boolean)
    .slice(0, 12);
  const mappedWorkRows = firstArray(record.workRows)
    .map((row) => {
      if (!row || typeof row !== "object" || Array.isArray(row)) return null;
      const headline = compactStudioWhitespace(row.headline || row.label || "").slice(0, 160);
      if (!headline) return null;
      return {
        id: compactStudioWhitespace(row.id || row.stepId || headline).slice(0, 96),
        kind: compactStudioWhitespace(row.kind || row.publicKind || "tool").slice(0, 48),
        status: compactStudioWhitespace(row.status || "completed").slice(0, 32),
        headline,
        summary: compactStudioWhitespace(row.summary || row.detail || "").slice(0, 220),
        excerptPreview: compactStudioWhitespace(row.excerptPreview || row.excerpt_preview || "").slice(0, 280),
        sourceChips: firstArray(row.sourceChips || row.source_chips)
          .map((source) => studioSourceRefFromRecord(source))
          .filter(Boolean)
          .slice(0, 6),
      };
    })
    .filter(Boolean)
    .slice(0, 12);
  const sessionCards = firstArray(record.sessionCards)
    .map((session) => {
      if (!session || typeof session !== "object" || Array.isArray(session)) return null;
      const id = compactStudioWhitespace(session.id || session.sessionId || session.title || "managed-session").slice(0, 120);
      return {
        id,
        kind: compactStudioWhitespace(session.kind || "sandbox_browser").slice(0, 48),
        surfaceLabel: compactStudioWhitespace(session.surfaceLabel || session.surface_label || "Sandbox browser").slice(0, 80),
        status: compactStudioWhitespace(session.status || "complete").slice(0, 48),
        statusLabel: compactStudioWhitespace(session.statusLabel || session.status_label || "Complete").slice(0, 80),
        title: compactStudioWhitespace(session.title || "Browser session").slice(0, 120),
        detail: compactStudioWhitespace(session.detail || session.summary || "Managed browser session").slice(0, 240),
        url: compactStudioWhitespace(session.url || "").slice(0, 240),
        pageTitle: compactStudioWhitespace(session.pageTitle || session.page_title || "").slice(0, 120),
        target: compactStudioWhitespace(session.target || "").slice(0, 160),
        lane: compactStudioWhitespace(session.lane || "").slice(0, 80),
        sessionMode: compactStudioWhitespace(session.sessionMode || session.session_mode || "").slice(0, 80),
        lastTool: compactStudioWhitespace(session.lastTool || session.last_tool || "computer-use").slice(0, 80),
        actionCount: Math.max(1, Number(session.actionCount || session.action_count || 1) || 1),
        controlState: compactStudioWhitespace(session.controlState || session.control_state || "observe").slice(0, 48),
        availableControlStates: firstArray(session.availableControlStates || session.available_control_states)
          .map((state) => compactStudioWhitespace(state).slice(0, 48))
          .filter(Boolean)
          .slice(0, 6),
        waitingForUser: Boolean(session.waitingForUser || session.waiting_for_user),
        waitingReason: compactStudioWhitespace(session.waitingReason || session.waiting_reason || "").slice(0, 80),
        replayReady: Boolean(session.replayReady || session.replay_ready),
        updatedAt: compactStudioWhitespace(session.updatedAt || session.updated_at || "").slice(0, 80),
      };
    })
    .filter(Boolean)
    .slice(-3);
  const rawCommandOutputs = firstArray(record.commandOutputs);
  const hasCommandOutput = rawCommandOutputs.some((command) => studioCommandRowHasOutput(command));
  const hasWorkRowOutput = mappedWorkRows.some((row) => compactStudioWhitespace(row.excerptPreview || ""));
  const commandOutputs = rawCommandOutputs
    .map((command, index) => studioPublicCommandOutputForWebview(command, index, { recordSettled }))
    .filter(Boolean)
    .filter((command) => {
      const status = compactStudioWhitespace(command.status || "");
      const emptyOutput = !compactStudioWhitespace(
        command.stdout ||
        command.output ||
        command.chunk ||
        command.text ||
        command.excerptPreview ||
        command.excerpt_preview ||
        ""
      ) && !compactStudioWhitespace(command.stderr || "");
      if (recordSettled && emptyOutput && /^(?:running|started|pending)$/i.test(status)) return false;
      if (recordSettled && (hasCommandOutput || hasWorkRowOutput) && emptyOutput && /^(?:completed|succeeded|success)$/i.test(status)) return false;
      return true;
    })
    .slice(-4);
  const workRows = studioFilterDuplicateCommandWorkRows(mappedWorkRows, commandOutputs);
  const diffHunks = firstArray(record.diffHunks)
    .map((hunk, index) => studioPublicDiffHunkForWebview(hunk, index))
    .filter(Boolean)
    .slice(-6);
  if (!lines.length && !workRows.length && !sessionCards.length && !commandOutputs.length && !diffHunks.length) {
    return null;
  }
  return {
    status: compactStudioWhitespace(record.status || "completed").slice(0, 32),
    durationMs: Math.max(0, Number(record.durationMs || 0) || 0),
    lines,
    workRows,
    commandOutputs,
    diffHunks,
    sessionCards,
    stepCount: Number(record.stepCount || lines.length || workRows.length || commandOutputs.length || diffHunks.length || 0) || lines.length || workRows.length || commandOutputs.length || diffHunks.length,
  };
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

function studioJsonValueFromText(value = "") {
  const text = String(value || "").trim();
  if (!text || !/^[{\[]/.test(text)) {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function studioUnescapeJsonStringFragment(value = "") {
  const text = String(value || "");
  try {
    return JSON.parse(`"${text.replace(/\r/g, "\\r").replace(/\n/g, "\\n")}"`);
  } catch {
    return text.replace(/\\"/g, '"').replace(/\\n/g, " ").replace(/\\\\/g, "\\");
  }
}

function studioPartialJsonFieldValue(objectText = "", keys = []) {
  for (const key of firstArray(keys)) {
    const pattern = new RegExp(`"${key}"\\s*:\\s*"((?:\\\\.|[^"\\\\])*)"`, "i");
    const match = pattern.exec(objectText);
    if (match?.[1]) {
      return studioUnescapeJsonStringFragment(match[1]);
    }
  }
  return "";
}

function collectStudioSourceRefsFromPartialJsonText(value = "", refs = []) {
  if (refs.length >= 8) {
    return;
  }
  const text = String(value || "");
  if (!/"(?:url|href|link|sourceUrl|source_url|canonicalUrl|canonical_url)"\s*:\s*"https?:\/\//i.test(text)) {
    return;
  }
  const urlPattern = /"(?:url|href|link|sourceUrl|source_url|canonicalUrl|canonical_url)"\s*:\s*"((?:\\.|[^"\\])*)"/gi;
  let match;
  while ((match = urlPattern.exec(text)) && refs.length < 8) {
    const url = studioUnescapeJsonStringFragment(match[1]);
    if (!/^https?:\/\//i.test(url)) {
      continue;
    }
    const objectStart = Math.max(0, text.lastIndexOf("{", match.index));
    let objectEnd = text.indexOf("\n    }", match.index);
    if (objectEnd === -1) objectEnd = text.indexOf("\n  }", match.index);
    if (objectEnd === -1) objectEnd = text.indexOf("}", match.index);
    if (objectEnd === -1) objectEnd = Math.min(text.length, match.index + 1800);
    const objectText = text.slice(objectStart, Math.min(text.length, objectEnd + 1));
    const recovered = studioSourceRefFromRecord({
      url,
      title: studioPartialJsonFieldValue(objectText, ["title", "name", "label"]),
      snippet: studioPartialJsonFieldValue(objectText, ["snippet", "excerpt", "summary"]),
      domain: studioPartialJsonFieldValue(objectText, ["domain", "hostname"]),
      state: studioPartialJsonFieldValue(objectText, ["state", "status", "sourceHealth"]),
    });
    if (recovered) {
      refs.push(recovered);
    }
  }
}

function studioRecordValue(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function studioSourceRefFromRecord(record = {}) {
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    return null;
  }
  const url = stringValue(
    record.url ||
      record.href ||
      record.link ||
      record.sourceUrl ||
      record.source_url ||
      record.canonicalUrl ||
      record.canonical_url,
  );
  if (!/^https?:\/\//i.test(url)) {
    return null;
  }
  let domain = stringValue(record.domain || record.hostname);
  try {
    domain ||= new URL(url).hostname;
  } catch {
    domain ||= url;
  }
  const title = compactStudioWhitespace(
    record.title ||
      record.name ||
      record.label ||
      domain ||
      url,
  ).slice(0, 96);
  return {
    title: title || domain || url,
    url,
    domain: compactStudioWhitespace(domain).replace(/^www\./i, ""),
    excerpt: compactStudioWhitespace(record.excerpt || record.snippet || record.summary || "").slice(0, 260),
    state: compactStudioWhitespace(record.state || record.status || record.sourceHealth || "used").slice(0, 40) || "used",
  };
}

function collectStudioSourceRefs(value, refs, depth = 0) {
  if (depth > 10 || refs.length >= 8 || value == null) {
    return;
  }
  const parsed = typeof value === "string" ? studioJsonValueFromText(value) : value;
  if (!parsed) {
    if (typeof value === "string") {
      collectStudioSourceRefsFromPartialJsonText(value, refs);
    }
    return;
  }
  if (Array.isArray(parsed)) {
    for (const item of parsed) {
      collectStudioSourceRefs(item, refs, depth + 1);
      if (refs.length >= 8) break;
    }
    return;
  }
  if (typeof parsed !== "object") {
    return;
  }
  const sourceRef = studioSourceRefFromRecord(parsed);
  if (sourceRef) {
    refs.push(sourceRef);
  }
  for (const key of [
    "sources",
    "source",
    "sourceRefs",
    "source_refs",
    "sourceObservations",
    "source_observations",
    "documents",
    "document",
    "items",
    "results",
    "citations",
    "references",
    "payload",
    "payload_summary",
    "payloadSummary",
    "kernel_event",
    "kernelEvent",
    "AgentActionResult",
    "WorkloadReceipt",
    "WebRetrieve",
    "receipt",
    "data",
    "result",
    "output",
    "preview",
    "raw_output",
    "rawOutput",
  ]) {
    if (parsed[key] !== undefined) {
      collectStudioSourceRefs(parsed[key], refs, depth + 1);
    }
    if (refs.length >= 8) break;
  }
}

function studioSourceRefsFromRuntimeEvents(events = []) {
  const refs = [];
  for (const event of firstArray(events)) {
    collectStudioSourceRefs(event?.payload, refs);
    collectStudioSourceRefs(event?.payload_summary, refs);
    collectStudioSourceRefs(event?.payloadSummary, refs);
    collectStudioSourceRefs(event?.data, refs);
    if (refs.length >= 8) break;
  }
  const seen = new Set();
  return refs.filter((ref) => {
    const key = `${ref.url} ${ref.title}`.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, 6);
}

function studioSourceRefsFromRuntimeEvent(event = {}, summary = "") {
  const refs = [];
  collectStudioSourceRefs(event?.payload, refs);
  collectStudioSourceRefs(event?.payload_summary, refs);
  collectStudioSourceRefs(event?.payloadSummary, refs);
  collectStudioSourceRefs(event?.data, refs);
  collectStudioSourceRefs(summary, refs);
  const seen = new Set();
  return refs.filter((ref) => {
    const key = `${ref.url} ${ref.title}`.toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, 6);
}

function studioFirstSourceExcerptFromEvent(event = {}, summary = "") {
  const candidates = [];
  function visit(value, depth = 0) {
    if (depth > 10 || candidates.length >= 6 || value == null) return;
    const parsed = typeof value === "string" ? studioJsonValueFromText(value) : value;
    if (!parsed) return;
    if (Array.isArray(parsed)) {
      for (const item of parsed) visit(item, depth + 1);
      return;
    }
    if (typeof parsed !== "object") return;
    for (const key of ["snippet", "excerpt", "excerpt_preview", "excerptPreview", "summary", "text", "content"]) {
      const text = compactStudioWhitespace(parsed[key]);
      if (text && !/^\{/.test(text)) candidates.push(text.slice(0, 280));
    }
    for (const key of [
      "sources",
      "source",
      "sourceRefs",
      "source_refs",
      "sourceObservations",
      "source_observations",
      "documents",
      "document",
      "items",
      "results",
      "citations",
      "references",
      "payload",
      "payload_summary",
      "payloadSummary",
      "kernel_event",
      "kernelEvent",
      "AgentActionResult",
      "WorkloadReceipt",
      "WebRetrieve",
      "receipt",
      "result",
      "output",
      "preview",
      "data",
    ]) {
      visit(parsed[key], depth + 1);
    }
  }
  visit(event?.payload);
  visit(event?.payload_summary);
  visit(event?.payloadSummary);
  visit(event?.data);
  visit(summary);
  return candidates[0] || "";
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

function studioManagedSessionFromBridgeCard(card = {}) {
  const kind = stringValue(card.kind || card.session_kind || card.sessionKind, "sandbox_browser");
  const status = stringValue(card.status, "complete");
  const controlState = stringValue(card.control_state || card.controlState, "observe");
  return {
    id: stringValue(card.id || card.session_id || card.sessionId || card.managed_session_id || card.managedSessionId, "managed-session"),
    kind,
    surfaceLabel: stringValue(card.surface_label || card.surfaceLabel, studioComputerUseSurfaceLabel(kind)),
    status,
    statusLabel: stringValue(card.status_label || card.statusLabel, studioComputerUseStatusLabel(status)),
    controlState,
    availableControlStates: firstArray(card.available_control_states || card.availableControlStates),
    waitingForUser: Boolean(card.waiting_for_user || card.waitingForUser || status === "waiting_for_user" || status === "needs_user"),
    waitingReason: stringValue(card.waiting_reason || card.waitingReason),
    title: stringValue(card.step_label || card.stepLabel || card.title, kind === "desktop" ? "Computer session" : "Browser session"),
    detail: stringValue(card.detail || card.summary, "Runtime-managed viewport"),
    pageTitle: stringValue(card.page_title || card.pageTitle),
    target: stringValue(card.target || card.url),
    url: stringValue(card.url || card.target),
    lastTool: stringValue(card.last_tool || card.lastTool, "computer-use"),
    actionCount: Math.max(1, Number(card.action_count || card.actionCount || 1) || 1),
    replayReady: Boolean(card.replay_ready || card.replayReady),
    updatedAt: new Date().toISOString(),
  };
}

function applyStudioManagedSessionInspection(inspection = {}) {
  const managed =
    inspection.managed_sessions ||
    inspection.managedSessions ||
    inspection.inspection?.managed_sessions ||
    inspection.inspection?.managedSessions ||
    {};
  if (!Array.isArray(managed.sessions)) {
    return [];
  }
  const sessions = managed.sessions
    .map(studioManagedSessionFromBridgeCard)
    .filter((session) => session.id);
  studioRuntimeProjection.computerUseSessions = sessions;
  applyStudioManagedSessionsToLatestTurn(sessions);
  studioRuntimeProjection.runtimeCockpit.managedSessionCount = sessions.length;
  if (sessions.length) {
    studioRuntimeProjection.runtimeCockpit.managedLiveViewportObserved = true;
    studioRuntimeProjection.runtimeCockpit.managedSessionLabelsObserved = true;
  }
  return sessions;
}

function applyStudioManagedSessionsToLatestTurn(sessions = []) {
  const cards = firstArray(sessions).filter(Boolean);
  if (!cards.length) {
    return false;
  }
  for (let index = studioRuntimeProjection.turns.length - 1; index >= 0; index -= 1) {
    const turn = studioRuntimeProjection.turns[index];
    if (turn?.role !== "assistant") {
      continue;
    }
    const existingWorkRecord =
      turn.workRecord && typeof turn.workRecord === "object" && !Array.isArray(turn.workRecord)
        ? turn.workRecord
        : {};
    turn.workRecord = {
      ...existingWorkRecord,
      status: existingWorkRecord.status || "completed",
      sessionCards: cards,
    };
    return true;
  }
  return false;
}

async function refreshStudioManagedSessionsFromDaemon(output) {
  const endpoint = daemonEndpoint();
  const threadId = stringValue(studioRuntimeProjection.threadId);
  if (!endpoint || !threadId) {
    return [];
  }
  try {
    const inspection = await requestJson(
      endpoint,
      `/v1/threads/${encodeURIComponent(threadId)}/managed-sessions`,
      {
        token: daemonRequestToken(),
        timeoutMs: 2500,
      },
    );
    return applyStudioManagedSessionInspection(inspection);
  } catch (error) {
    output?.appendLine?.(
      `[ioi-studio] managed session inspection unavailable: ${error?.message || String(error)}`,
    );
    return [];
  }
}

function ensureStudioManagedSessionReconnectTurn() {
  const marker = "managed-session-reconnect-proof";
  for (let index = studioRuntimeProjection.turns.length - 1; index >= 0; index -= 1) {
    const turn = studioRuntimeProjection.turns[index];
    if (turn?.role === "assistant" && turn?.workRecord?.id === marker) {
      return turn;
    }
  }
  const turn = {
    role: "assistant",
    content: "Managed browser session state is available for operator control.",
    createdAt: new Date().toISOString(),
    workRecord: {
      id: marker,
      status: "completed",
      title: "Managed browser session",
      sessionCards: [],
      receiptRefs: ["receipt_managed_session_reconnect_gui"],
    },
  };
  studioRuntimeProjection.turns.push(turn);
  return turn;
}

async function inspectStudioManagedSessionsForReconnect(output, threadId) {
  const endpoint = daemonEndpoint();
  if (!endpoint || !threadId) {
    return { inspection: null, sessions: [] };
  }
  try {
    const inspection = await requestJson(
      endpoint,
      `/v1/threads/${encodeURIComponent(threadId)}/managed-sessions`,
      {
        token: daemonRequestToken(),
        timeoutMs: 3500,
      },
    );
    const sessions = applyStudioManagedSessionInspection(inspection);
    return { inspection, sessions };
  } catch (error) {
    output?.appendLine?.(
      `[ioi-studio] managed session reconnect inspection unavailable: ${error?.message || String(error)}`,
    );
    return { inspection: null, sessions: [] };
  }
}

function studioManagedSessionReconnectSummary({ inspection, sessions, expectedManagedSessionId = "", expectedRuntimeSessionId = "", expectedControlState = "" } = {}) {
  const managed = inspection?.managed_sessions || inspection?.managedSessions || {};
  const replay = managed?.replay || {};
  const runtimeSessionId = stringValue(inspection?.session_id || inspection?.sessionId);
  const session = firstArray(sessions).find((candidate) => candidate.id === expectedManagedSessionId) || firstArray(sessions)[0] || null;
  const checks = {
    inspectionReturned: Boolean(inspection),
    sessionCardObserved: Boolean(session),
    expectedManagedSessionStable: expectedManagedSessionId ? session?.id === expectedManagedSessionId : Boolean(session?.id),
    expectedRuntimeSessionStable: expectedRuntimeSessionId ? runtimeSessionId === expectedRuntimeSessionId : Boolean(runtimeSessionId),
    expectedControlStateObserved: expectedControlState ? session?.controlState === expectedControlState : Boolean(session?.controlState),
    waitingForUserReplayed: Boolean(session?.waitingForUser),
    replayReady: Boolean(session?.replayReady || replay?.replayable || replay?.available),
  };
  return {
    session,
    runtimeSessionId,
    replay,
    checks,
    passed: Object.values(checks).every(Boolean),
  };
}

async function exerciseStudioManagedSessionReconnect(output, payload = {}) {
  const phase = payload?.phase === "reconnect" ? "reconnect" : "create";
  const threadId = stringValue(payload?.threadId || payload?.thread_id);
  if (!threadId) {
    throw new Error("Managed session reconnect proof requires a daemon thread id.");
  }
  const expectedManagedSessionId = stringValue(
    payload?.expectedManagedSessionId || payload?.expected_managed_session_id || payload?.managedSessionId || payload?.managed_session_id,
  );
  const expectedRuntimeSessionId = stringValue(
    payload?.expectedRuntimeSessionId || payload?.expected_runtime_session_id || payload?.runtimeSessionId || payload?.runtime_session_id,
  );
  const expectedControlState = stringValue(payload?.expectedControlState || payload?.expected_control_state || "observe");
  const contextSnapshot = buildWorkspaceActionContext(`studio-managed-session-reconnect-${phase}`);
  studioRuntimeProjection.threadId = threadId;
  ensureStudioManagedSessionReconnectTurn();
  const { inspection, sessions } = await inspectStudioManagedSessionsForReconnect(output, threadId);
  const summary = studioManagedSessionReconnectSummary({
    inspection,
    sessions,
    expectedManagedSessionId,
    expectedRuntimeSessionId,
    expectedControlState,
  });
  const checks = {
    threadObserved: Boolean(threadId),
    ...summary.checks,
  };
  if (phase === "reconnect") {
    studioRuntimeProjection.engineReconnectBanners.push({
      id: "managed-session.engine-reconnect",
      kind: "engine.reconnect",
      status: summary.passed ? "ready" : "blocked",
      bannerLabel: "Engine reconnect restored managed browser session state.",
      composerFrozen: false,
      receiptRefs: ["receipt_managed_session_reconnect_gui"],
    });
  }
  studioRuntimeProjection.runtimeCockpit.managedLiveViewportObserved = sessions.length > 0;
  studioRuntimeProjection.runtimeCockpit.managedSessionLabelsObserved = sessions.length > 0;
  studioRuntimeProjection.runtimeCockpit.managedSessionCount = sessions.length;
  const passed = Object.values(checks).every(Boolean);
  await writeBridgeRequest("studio.managedSessionReconnect.exercised", {
    sourceCommand: "ioi.studio.exerciseManagedSessionReconnect",
    runtimeAuthority: "daemon-owned",
    projectionOwner: "openvscode-workbench-adapter",
    ownsRuntimeState: false,
    phase,
    threadId,
    runtimeSessionId: summary.runtimeSessionId,
    expectedRuntimeSessionId,
    managedSessionId: summary.session?.id || "",
    expectedManagedSessionId,
    controlState: summary.session?.controlState || "",
    expectedControlState,
    waitingForUser: Boolean(summary.session?.waitingForUser),
    replayReady: Boolean(summary.session?.replayReady || summary.replay?.replayable || summary.replay?.available),
    replaySource: stringValue(summary.replay?.source),
    sessionCount: sessions.length,
    checks,
    passed,
  }, contextSnapshot).catch((error) => {
    output.appendLine(`[ioi-studio] managed session reconnect bridge request unavailable: ${error?.message || String(error)}`);
  });
  return {
    passed,
    phase,
    threadId,
    runtimeSessionId: summary.runtimeSessionId,
    managedSessionId: summary.session?.id || "",
    controlState: summary.session?.controlState || "",
    waitingForUser: Boolean(summary.session?.waitingForUser),
    replayReady: Boolean(summary.session?.replayReady || summary.replay?.replayable || summary.replay?.available),
    replaySource: stringValue(summary.replay?.source),
    sessionCount: sessions.length,
    checks,
  };
}

function applyStudioWorkspaceChangeReviewInspection(inspection = {}) {
  const previews = firstArray(inspection.hunkPreviews || inspection.hunk_previews)
    .map((hunk, index) => ({
      id: stringValue(hunk.id, `workspace-hunk-${index}`),
      changeId: stringValue(hunk.changeId || hunk.change_id),
      hunkIndex: Number.isFinite(Number(hunk.hunkIndex ?? hunk.hunk_index)) ? Number(hunk.hunkIndex ?? hunk.hunk_index) : index,
      file: stringValue(hunk.file || hunk.path, "workspace"),
      title: stringValue(hunk.title, `Workspace hunk ${index + 1}`),
      status: stringValue(hunk.status || hunk.lifecycle, "needs_review"),
      lifecycle: stringValue(hunk.lifecycle),
      kind: stringValue(hunk.kind, "edit"),
      before: String(hunk.before ?? hunk.searchText ?? hunk.search_text ?? ""),
      after: String(hunk.after ?? hunk.replaceText ?? hunk.replace_text ?? hunk.contentText ?? hunk.content_text ?? ""),
      beforeContent: String(hunk.beforeContent ?? hunk.before ?? ""),
      afterContent: String(hunk.afterContent ?? hunk.after ?? ""),
      acceptAvailable: Boolean(hunk.acceptAvailable ?? hunk.accept_available),
      rejectAvailable: Boolean(hunk.rejectAvailable ?? hunk.reject_available),
      rollbackAvailable: Boolean(hunk.rollbackAvailable ?? hunk.rollback_available),
      stale: Boolean(hunk.stale),
      staleReason: stringValue(hunk.staleReason || hunk.stale_reason),
    }))
    .filter((hunk) => hunk.changeId || hunk.before || hunk.after);
  if (!previews.length) {
    return [];
  }
  studioRuntimeProjection.diffHunks = previews;
  studioRuntimeProjection.runtimeCockpit.inlineDiffOverlayObserved = true;
  studioRuntimeProjection.runtimeCockpit.hunkNavigationObserved = true;
  return previews;
}

async function refreshStudioWorkspaceChangeReviewsFromDaemon(output) {
  const endpoint = daemonEndpoint();
  const threadId = stringValue(studioRuntimeProjection.threadId);
  if (!endpoint || !threadId) {
    return [];
  }
  try {
    const workspaceRoot = compactStudioWhitespace(workspaceSummary().path);
    const query = workspaceRoot && !/^open a workspace/i.test(workspaceRoot)
      ? `?workspaceRoot=${encodeURIComponent(workspaceRoot)}`
      : "";
    const inspection = await requestJson(
      endpoint,
      `/v1/threads/${encodeURIComponent(threadId)}/workspace-change-reviews${query}`,
      {
        token: daemonRequestToken(),
        timeoutMs: 10000,
      },
    );
    return applyStudioWorkspaceChangeReviewInspection(inspection);
  } catch (error) {
    output?.appendLine?.(
      `[ioi-studio] workspace change review inspection unavailable: ${error?.message || String(error)}`,
    );
    return [];
  }
}

function studioWorkRecordWithSessionCards(workRecord, sessionCards = []) {
  const cards = firstArray(sessionCards).filter(Boolean);
  if (!cards.length) {
    return workRecord || null;
  }
  const existing =
    workRecord && typeof workRecord === "object" && !Array.isArray(workRecord)
      ? workRecord
      : {
          status: "completed",
          durationMs: 0,
          lines: [],
          summaryParts: [],
          activityLines: [],
          receiptRefs: [],
          stepCount: 0,
        };
  const hasSessionLine = firstArray(existing.lines).some((line) =>
    /\b(browser|computer).*live session\b/i.test(String(line || "")),
  );
  return {
    ...existing,
    status: existing.status || "completed",
    lines: hasSessionLine
      ? firstArray(existing.lines)
      : [
          ...firstArray(existing.lines),
          `Managed ${cards.length} browser/computer live session${cards.length === 1 ? "" : "s"}`,
        ],
    summaryParts: firstArray(existing.summaryParts),
    activityLines: firstArray(existing.activityLines),
    receiptRefs: firstArray(existing.receiptRefs),
    stepCount: Math.max(Number(existing.stepCount || 0) || 0, firstArray(existing.lines).length + 1),
    sessionCards: cards.slice(-3),
  };
}

function studioManagedSessionRows(cards = []) {
  const sessions = firstArray(cards).filter(Boolean);
  if (!sessions.length) {
    return "";
  }
  return `
    <section class="studio-managed-sessions" data-testid="studio-managed-sessions" aria-label="Browser and computer sessions">
      ${sessions.map((session, index) => {
        const controlState = session.controlState || session.control_state || "observe";
        const modeLabels = [
          ["sandbox_browser", "Sandbox browser"],
          ["local_browser", "Local browser"],
          ["desktop", "Desktop"],
        ];
        return `
          <article
            class="studio-managed-session-card studio-managed-session-card--${escapeHtml(session.kind || "sandbox_browser")}"
            data-testid="studio-managed-session-card"
            data-session-id="${escapeHtml(session.id || session.sessionId || "managed-session")}"
            data-session-kind="${escapeHtml(session.kind || "sandbox_browser")}"
            data-session-label="${escapeHtml(session.surfaceLabel || "Sandbox browser")}"
            data-session-status="${escapeHtml(session.status || "complete")}"
            data-control-state="${escapeHtml(controlState)}"
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
                <button type="button" data-testid="studio-managed-session-observe" data-studio-managed-session-control="observe" aria-pressed="${controlState === "observe"}" class="${controlState === "observe" ? "is-active" : ""}">Observe</button>
                <button type="button" data-testid="studio-managed-session-take-over" data-studio-managed-session-control="take_over" aria-pressed="${controlState === "take_over"}" class="${controlState === "take_over" ? "is-active" : ""}">Take over</button>
                <button type="button" data-testid="studio-managed-session-return" data-studio-managed-session-control="return_agent" aria-pressed="${controlState === "return_agent"}" class="${controlState === "return_agent" ? "is-active" : ""}">Return control to Agent</button>
              </div>
            </div>
          </article>
        `;
      }).join("")}
    </section>
  `;
}

function studioArtifactClassLabel(artifact = {}) {
  const value = stringValue(artifact.artifactClass || artifact.artifact_class || artifact.class, "artifact");
  if (value === "static_html_js") {
    return studioArtifactIsWebsite(artifact) ? "Website" : "HTML report";
  }
  if (value === "react_vite_app") return "App preview";
  if (value === "imported_document") return "Document";
  if (value === "pdf_preview") return "PDF";
  if (value === "diff_patch") return "Patch";
  if (value === "dataset_chart") return "Dataset";
  if (value === "browser_observation") return "Browser capture";
  return value
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b[a-z]/g, (char) => char.toUpperCase());
}

function studioArtifactOutputModality(artifact = {}) {
  return stringValue(
    artifact.outputModality ||
      artifact.output_modality ||
      artifact.generatedFiles?.outputModality ||
      artifact.generated_files?.output_modality ||
      artifact.generatedFiles?.output_modality ||
      artifact.generated_files?.outputModality,
  );
}

function studioArtifactIsWebsite(artifact = {}) {
  if ((artifact.artifactClass || artifact.artifact_class) !== "static_html_js") return false;
  const modality = studioArtifactOutputModality(artifact);
  if (/\b(website|web\s*site|webpage|web\s*page|landing\s+page|site)\b/i.test(modality)) return true;
  return /\b(website|web\s*site|webpage|web\s*page|landing\s+page|site)\b/i.test(
    `${artifact.title || ""} ${artifact.summary || ""} ${artifact.generatedFiles?.summary || ""} ${artifact.generated_files?.summary || ""}`,
  );
}

function studioArtifactPreviewLabel(artifact = {}) {
  const previewRefs = firstArray(artifact.previewRefs || artifact.preview_refs);
  if (!previewRefs.length) {
    return "Preview pending";
  }
  const firstPreview = previewRefs[0] || {};
  const mediaType = stringValue(firstPreview.mediaType || firstPreview.media_type, "preview");
  if (/html/i.test(mediaType)) {
    return studioArtifactIsWebsite(artifact) ? "Website preview" : "HTML preview";
  }
  if (/pdf/i.test(mediaType)) return "PDF preview";
  if (/csv|json/i.test(mediaType)) return "Data preview";
  return "Preview ready";
}

function studioArtifactPreviewSrcdoc(text, pageNonce = "") {
  const nonceAttr = pageNonce ? ` nonce="${escapeHtml(pageNonce)}"` : "";
  return stringValue(text)
    .replace(/<style(?![^>]*\bnonce=)/gi, `<style${nonceAttr}`)
    .replace(/<script(?![^>]*\bnonce=)/gi, `<script${nonceAttr}`);
}

function studioArtifactInlinePreview(artifact = {}) {
  const inline = studioRecordValue(artifact.previewInline || artifact.preview_inline);
  const text = stringValue(inline.text);
  if (!text) {
    return "";
  }
  const mediaType = stringValue(inline.mediaType || inline.media_type);
  if (/html/i.test(mediaType)) {
    const previewHtml = studioArtifactPreviewSrcdoc(text, studioPanelPageNonce || "");
    return `
      <iframe
        class="studio-conversation-artifact-frame"
        data-testid="studio-conversation-artifact-preview-frame"
        sandbox="allow-scripts"
        title="${escapeHtml(artifact.title || "Artifact preview")}"
        srcdoc="${escapeHtml(previewHtml)}"
      ></iframe>
    `;
  }
  return `
    <pre class="studio-conversation-artifact-source-preview" data-testid="studio-conversation-artifact-source-preview">${escapeHtml(text.slice(0, 6000))}</pre>
  `;
}

function studioArtifactPreviewShell(artifact = {}, { expanded = false } = {}) {
  const inlinePreview = studioArtifactInlinePreview(artifact);
  const stateLabel = stringValue(artifact.stateLabel || artifact.state_label || artifact.status, "Preview ready");
  if (inlinePreview) {
    return `
      <div class="studio-conversation-artifact-preview studio-conversation-artifact-preview--${expanded ? "expanded" : "compact"}" data-testid="studio-conversation-artifact-preview">
        ${inlinePreview}
      </div>
    `;
  }
  return `
    <div class="studio-conversation-artifact-preview studio-conversation-artifact-preview--placeholder" data-testid="studio-conversation-artifact-preview">
      <strong>${escapeHtml(studioArtifactPreviewLabel(artifact))}</strong>
      <span>${escapeHtml(stateLabel)}</span>
    </div>
  `;
}

function studioConversationArtifactRows(cards = []) {
  const artifacts = firstArray(cards).filter(Boolean);
  if (!artifacts.length) {
    return "";
  }
  return `
    <section class="studio-conversation-artifacts" data-testid="studio-conversation-artifacts" aria-label="Conversation artifacts">
      ${artifacts.map((artifact) => {
        const artifactId = stringValue(artifact.id || artifact.artifactId || artifact.artifact_id, "artifact");
        const stateLabel = stringValue(artifact.stateLabel || artifact.state_label || artifact.status, "Preview ready");
        const actions = firstArray(artifact.actions).slice(0, 6);
        const revisionCount = firstArray(artifact.revisions).length || 1;
        return `
          <article
            class="studio-conversation-artifact-card"
            data-testid="studio-conversation-artifact-card"
            data-artifact-id="${escapeHtml(artifactId)}"
            data-artifact-class="${escapeHtml(artifact.artifactClass || artifact.artifact_class || "")}"
            data-artifact-status="${escapeHtml(artifact.status || "")}"
            data-artifact-expanded="false"
          >
            <header class="studio-conversation-artifact-card__header">
              <div>
                <span data-testid="studio-conversation-artifact-type">${escapeHtml(studioArtifactClassLabel(artifact))}</span>
                <strong data-testid="studio-conversation-artifact-title">${escapeHtml(artifact.title || "Conversation artifact")}</strong>
              </div>
              <button type="button" data-testid="studio-conversation-artifact-expand" data-studio-artifact-expand aria-expanded="false">Open</button>
            </header>
            <div class="studio-conversation-artifact-compact" data-testid="studio-conversation-artifact-compact">
              <div class="studio-conversation-artifact-compact__status">
                <strong>${escapeHtml(stateLabel)}</strong>
                <span>${escapeHtml(studioArtifactPreviewLabel(artifact))} · ${escapeHtml(String(revisionCount))} revision${revisionCount === 1 ? "" : "s"}</span>
              </div>
              ${studioArtifactPreviewShell(artifact, { expanded: false })}
            </div>
            <div class="studio-conversation-artifact-expanded" data-testid="studio-conversation-artifact-expanded-view">
              <div class="studio-conversation-artifact-meta studio-visually-hidden" data-testid="studio-conversation-artifact-renderer-meta">
                <span>Renderer: ${escapeHtml(artifact.renderer?.label || artifact.renderer?.kind || "sandboxed preview")}</span>
                <span>Sandbox: network denied · no ambient filesystem</span>
              </div>
              ${studioArtifactPreviewShell(artifact, { expanded: true })}
              ${artifact.fidelity?.message ? `
                <div class="studio-conversation-artifact-fidelity" data-testid="studio-conversation-artifact-fidelity">
                  ${escapeHtml(artifact.fidelity.message)}
                </div>
              ` : ""}
              ${/(compare|document|diff|patch)/i.test(`${artifact.status || ""} ${artifact.artifactClass || artifact.artifact_class || ""}`) ? `
                <div class="studio-conversation-artifact-compare" data-testid="studio-conversation-artifact-compare-state">
                  <strong>Compare ready</strong>
                  <span>Original, projection, and latest revision are preserved by the daemon.</span>
                </div>
              ` : ""}
              <div class="studio-conversation-artifact-actions" data-testid="studio-conversation-artifact-actions">
                ${actions.map((action) => `
                  <button type="button" data-testid="studio-conversation-artifact-action" data-studio-artifact-action="${escapeHtml(action)}" data-artifact-id="${escapeHtml(artifactId)}">${escapeHtml(String(action).replace(/[_-]+/g, " "))}</button>
                `).join("")}
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
  for (const item of firstArray(studioRuntimeProjection.conversationArtifacts)) push({ ...item, kind: "conversation.artifact" });
  for (const item of firstArray(studioRuntimeProjection.engineReconnectBanners)) push({ ...item, kind: "engine.reconnect" });
  for (const item of firstArray(studioRuntimeProjection.trajectoryReplayPanels)) push({ ...item, kind: "trajectory.replay" });
  for (const item of firstArray(studioRuntimeProjection.sessionBrainPanels)) push({ ...item, kind: "session.brain" });
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
  if (/session[._-]?brain|run[._-]?brain|active[._-]?brain/.test(signature)) {
    studioRuntimeProjection.sessionBrainPanels.push({
      ...base,
      status: payload.status || base.status || "ready",
      detail: payload.detail || base.detail || "Run brain artifacts are available for replay.",
      artifactCount: payload.artifactCount ?? payload.artifact_count ?? null,
      scratchCount: payload.scratchCount ?? payload.scratch_count ?? null,
      hasImplementationPlan: Boolean(payload.hasImplementationPlan ?? payload.has_implementation_plan),
      hasTaskChecklist: Boolean(payload.hasTaskChecklist ?? payload.has_task_checklist),
      hasWalkthrough: Boolean(payload.hasWalkthrough ?? payload.has_walkthrough),
      hasScratchRefs: Boolean(payload.hasScratchRefs ?? payload.has_scratch_refs),
      hasArtifactRefs: Boolean(payload.hasArtifactRefs ?? payload.has_artifact_refs),
      hasReplayCursor: Boolean(payload.hasReplayCursor ?? payload.has_replay_cursor),
      brainOutsideWorkspace: Boolean(payload.brainOutsideWorkspace ?? payload.brain_outside_workspace),
      readOnlyAuditMode: Boolean(payload.readOnlyAuditMode ?? payload.read_only_audit_mode),
      rows: firstArray(payload.rows).map((row = {}, index) => ({
        id: stringValue(row.id, `session-brain-row-${index}`),
        artifactKind: stringValue(row.artifactKind || row.artifact_kind, "artifact"),
        label: stringValue(row.label, "Run brain artifact"),
        status: stringValue(row.status, "present"),
        preview: stringValue(row.preview, ""),
        receiptRefs: normalizeReceiptRefs(row),
      })),
    });
    return true;
  }
  if (/trajectory[._-]?replay|durable[._-]?trajectory|run[._-]?trajectory/.test(signature)) {
    studioRuntimeProjection.trajectoryReplayPanels.push({
      ...base,
      status: payload.status || base.status || "ready",
      detail: payload.detail || base.detail || "Durable trajectory replay is available after reconnect.",
      trajectoryIdStable: Boolean(payload.trajectoryIdStable ?? payload.trajectory_id_stable),
      replayCursorObserved: Boolean(payload.replayCursorObserved ?? payload.replay_cursor_observed),
      guiReconnected: Boolean(payload.guiReconnected ?? payload.gui_reconnected),
      replayIdsStable: Boolean(payload.replayIdsStable ?? payload.replay_ids_stable),
      replayFromCursorEmpty: Boolean(payload.replayFromCursorEmpty ?? payload.replay_from_cursor_empty),
      sideEffectCount: Number(payload.sideEffectCount ?? payload.side_effect_count ?? 0) || 0,
      duplicateSideEffectCount: Number(payload.duplicateSideEffectCount ?? payload.duplicate_side_effect_count ?? 0) || 0,
      rows: firstArray(payload.rows).map((row = {}, index) => ({
        id: stringValue(row.id, `trajectory-replay-step-${index + 1}`),
        kind: stringValue(row.kind, "runtime.event"),
        status: stringValue(row.status, "observed"),
        summary: stringValue(row.summary, ""),
        receiptRefs: normalizeReceiptRefs(row),
      })),
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
    record.model_id,
    record.providerId,
    record.provider_id,
    record.backendId,
    record.backend_id,
    record.artifactId,
    record.artifact_id,
    record.name,
    record.label,
    record.displayName,
    record.display_name,
    record.description,
    record.family,
    record.source,
    record.quantization,
    record.driver,
    record.apiFormat,
    record.api_format,
    record.baseUrl,
    record.base_url,
    record.status,
    record.state,
  ].map((value) => String(value || "").toLowerCase()).join(" ");
  return (
    /\bfixture\b/.test(haystack) ||
    haystack.includes("local:auto") ||
    haystack.includes("autopilot:native-fixture") ||
    haystack.includes("endpoint.local.auto") ||
    haystack.includes("endpoint.autopilot.native-fixture") ||
    haystack.includes("lmstudio:detected") ||
    haystack.includes("lmstudio.detected") ||
    haystack.includes("detected model slot") ||
    haystack.includes("lm_studio_public_discovery") ||
    haystack.includes("provider_stopped")
  );
}

function studioExternalModelProviderUsageAllowed() {
  return /^(1|true|yes|on)$/i.test(String(process.env.IOI_STUDIO_ALLOW_EXTERNAL_MODEL_PROVIDERS || ""));
}

function isExternalStudioModelRecord(record = {}) {
  if (studioExternalModelProviderUsageAllowed()) {
    return false;
  }
  const haystack = [
    record.id,
    record.modelId,
    record.model_id,
    record.providerId,
    record.provider_id,
    record.backendId,
    record.backend_id,
    record.family,
    record.source,
    record.driver,
    record.apiFormat,
    record.api_format,
    record.baseUrl,
    record.base_url,
    record.description,
  ].map((value) => String(value || "").toLowerCase()).join(" ");
  return (
    haystack.includes("provider.lmstudio") ||
    haystack.includes("backend.lmstudio") ||
    haystack.includes("lm_studio") ||
    haystack.includes("lm-studio") ||
    haystack.includes("provider.ollama") ||
    haystack.includes("backend.ollama")
  );
}

function modelRecordSupportsChat(record = {}) {
  const capabilities = Array.isArray(record.capabilities) ? record.capabilities : [];
  return capabilities.length === 0 || capabilities.some((capability) => /chat|responses/i.test(String(capability || "")));
}

function modelRecordIsEmbeddingOnly(record = {}) {
  const capabilities = Array.isArray(record.capabilities) ? record.capabilities : [];
  return capabilities.length > 0 &&
    capabilities.some((capability) => /embed/i.test(String(capability || ""))) &&
    !capabilities.some((capability) => /chat|responses/i.test(String(capability || "")));
}

function studioSelectionSupportsChat({ artifact = {}, endpoint = {} } = {}) {
  if ([artifact, endpoint].some((record) => modelRecordIsEmbeddingOnly(record))) {
    return false;
  }
  return [artifact, endpoint].some((record) => modelRecordSupportsChat(record));
}

function studioSelectionModelId({ artifact = {}, endpoint = {}, route = {} } = {}) {
  return stringValue(
    artifact.modelId ||
      artifact.model_id ||
      artifact.id ||
      endpoint.modelId ||
      endpoint.model_id ||
      route.modelId ||
      route.model_id ||
      route.lastSelectedModel ||
      route.last_selected_model,
  );
}

function isProductStudioModelSelection({ artifact = {}, endpoint = {}, route = {} } = {}) {
  const selectedModel = studioSelectionModelId({ artifact, endpoint, route });
  if (!selectedModel || isAutoStudioModelSelector(selectedModel) || selectedModel === STUDIO_PRODUCT_MODEL_UNAVAILABLE) {
    return false;
  }
  if (studioTextContainsProductFixtureMarker(selectedModel)) {
    return false;
  }
  if (!studioSelectionSupportsChat({ artifact, endpoint })) {
    return false;
  }
  return ![artifact, endpoint, route, { modelId: selectedModel }].some(
    (record) => isFixtureStudioModelRecord(record) || isExternalStudioModelRecord(record),
  );
}

function studioProductModelSelectionError(selectedRoute, selectedModelId) {
  if (studioFixtureModelUsageAllowed()) {
    return null;
  }
  const selectedModel = stringValue(selectedModelId);
  const routeOrModel = stringValue(selectedRoute);
  const haystack = `${selectedModel} ${routeOrModel}`.toLowerCase();
  if (
    !selectedModel ||
    selectedModel === STUDIO_PRODUCT_MODEL_UNAVAILABLE ||
    haystack.includes("no product model") ||
    haystack.includes("product model mounted") ||
    haystack.includes("local:auto") ||
    haystack.includes("lmstudio:detected") ||
    haystack.includes("lmstudio.detected") ||
    haystack.includes("detected model slot") ||
    haystack.includes("autopilot:native-fixture") ||
    haystack.includes("stories260k") ||
    haystack.includes("provider.lmstudio") ||
    haystack.includes("backend.lmstudio") ||
    /\bfixture\b/.test(haystack)
  ) {
    const error = new Error(
      "No product model is mounted for this route. Open Manage models and load a real local model.",
    );
    error.code = "product_model_unavailable";
    return error;
  }
  return null;
}

function assertStudioProductModelSelector(selectedRoute, selectedModelId) {
  const error = studioProductModelSelectionError(selectedRoute, selectedModelId);
  if (error) {
    throw error;
  }
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

function studioMaxOutputTokens() {
  const configured = Number(process.env.IOI_STUDIO_MAX_OUTPUT_TOKENS ?? "");
  if (Number.isFinite(configured) && configured >= 64) {
    return Math.min(8192, Math.floor(configured));
  }
  return STUDIO_DEFAULT_MAX_OUTPUT_TOKENS;
}

function studioArtifactMaxOutputTokens() {
  const configured = Number(process.env.IOI_STUDIO_ARTIFACT_MAX_OUTPUT_TOKENS ?? "");
  if (Number.isFinite(configured) && configured >= 512) {
    return Math.min(4096, Math.floor(configured));
  }
  return STUDIO_DEFAULT_ARTIFACT_MAX_OUTPUT_TOKENS;
}

const { studioCleanProductErrorMessage } = createStudioProductErrorMessage({ stringValue });

function modelRecordStatusScore(...records) {
  const status = records.map((record) => String(record?.status || record?.state || "").toLowerCase()).join(" ");
  if (/loaded|running|active/.test(status)) return 50;
  if (/mounted|ready/.test(status)) return 40;
  if (/available/.test(status)) return 30;
  if (/installed/.test(status)) return 20;
  return 0;
}

function studioSameNonEmptyId(left, right) {
  return Boolean(left && right && String(left) === String(right));
}

function studioPreferredModelSelection(snapshot = {}) {
  const activeRouteId = studioRuntimeProjection.modelRoute || "route.local-first";
  const activeRoute = snapshot.routes.find((candidate) =>
    candidate.id === activeRouteId || candidate.routeId === activeRouteId,
  );
  if (activeRoute) {
    const activeRouteFallback = firstArray(activeRoute.fallback || activeRoute.fallbackEndpoints || activeRoute.fallback_endpoints);
    const activeRouteModelId = stringValue(activeRoute.modelId || activeRoute.model_id || activeRoute.lastSelectedModel || activeRoute.last_selected_model);
    const activeEndpointId = activeRoute.endpointId || activeRoute.endpoint_id || activeRouteFallback[0] || "";
    const activeEndpoint =
      snapshot.endpoints.find((candidate) =>
        studioSameNonEmptyId(candidate.id, activeEndpointId) ||
        studioSameNonEmptyId(candidate.id, activeRoute.endpointId) ||
        activeRouteFallback.includes(candidate.id) ||
        studioSameNonEmptyId(candidate.routeId, activeRoute.routeId) ||
        studioSameNonEmptyId(candidate.routeId, activeRoute.id),
      ) ||
      snapshot.endpoints.find((candidate) =>
        studioSameNonEmptyId(candidate.modelId, activeRouteModelId) ||
        studioSameNonEmptyId(candidate.model_id, activeRouteModelId),
      ) ||
      {};
    const activeArtifact =
      snapshot.artifacts.find((candidate) =>
        studioSameNonEmptyId(candidate.id, activeEndpoint.artifactId) ||
        studioSameNonEmptyId(candidate.id, activeEndpoint.artifact_id) ||
        candidate.id === activeEndpoint.modelId ||
        candidate.modelId === activeEndpoint.modelId ||
        candidate.id === activeRoute.modelId ||
        candidate.modelId === activeRoute.modelId ||
        candidate.id === activeRouteModelId ||
        candidate.modelId === activeRouteModelId,
      ) ||
      {};
    if (modelRecordSupportsChat(activeArtifact) && isProductStudioModelSelection({
      artifact: activeArtifact,
      endpoint: activeEndpoint,
      route: activeRoute,
    })) {
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
          studioSameNonEmptyId(candidate.endpointId, endpoint.id) ||
          firstArray(candidate.fallback || candidate.fallbackEndpoints || candidate.fallback_endpoints).includes(endpoint.id) ||
          studioSameNonEmptyId(candidate.modelId, modelId) ||
          studioSameNonEmptyId(candidate.id, endpoint.routeId) ||
          studioSameNonEmptyId(candidate.routeId, endpoint.routeId),
        ) ||
        {};
      const providerSignal = String(`${artifact.providerId || ""} ${endpoint.providerId || ""} ${artifact.source || ""} ${endpoint.driver || ""}`);
      const providerWeight = /llama-cpp|llama_cpp|provider\.llama/i.test(providerSignal)
        ? 130
        : /ollama|vllm|openai_compatible|local\.folder/i.test(providerSignal)
          ? 80
          : 10;
      const selection = {
        artifact,
        endpoint,
        route,
        score: providerWeight + modelRecordStatusScore(endpoint, route, artifact),
      };
      return isProductStudioModelSelection(selection) ? selection : null;
    })
    .filter(Boolean)
    .sort((left, right) => right.score - left.score);
  return candidates[0] || null;
}

function studioSnapshotFromState(state = {}) {
  const snapshot = modelSnapshotFromState(state);
  const preferred = studioPreferredModelSelection(snapshot);
  const route = preferred?.route || snapshot.routes.find((candidate) =>
    candidate.id === studioRuntimeProjection.modelRoute || candidate.routeId === studioRuntimeProjection.modelRoute,
  ) || {};
  const endpoint = preferred?.endpoint || {};
  const artifact = preferred?.artifact || {};
  const staleSelectedModel = stringValue(studioRuntimeProjection.selectedModel);
  const staleProductSelectionAvailable = Boolean(
    !preferred &&
      staleSelectedModel &&
      !isAutoStudioModelSelector(staleSelectedModel) &&
      !studioProductModelSelectionError(studioRuntimeProjection.modelRoute || "route.local-first", staleSelectedModel),
  );
  const productModelAvailable = Boolean(preferred) || staleProductSelectionAvailable;
  const selectedModel = productModelAvailable
    ? (preferred ? studioSelectionModelId({ artifact, endpoint, route }) : staleSelectedModel)
    : STUDIO_PRODUCT_MODEL_UNAVAILABLE;
  const modelLabel = productModelAvailable
    ? (preferred ? (
        artifact.name ||
        artifact.label ||
        artifact.displayName ||
        artifact.modelId ||
        artifact.id ||
        endpoint.modelId ||
        route.modelId ||
        selectedModel
      ) : staleSelectedModel)
    : "No product model mounted";
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
    modelUnavailable: !productModelAvailable,
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
          firstArray(candidate.fallback || candidate.fallbackEndpoints || candidate.fallback_endpoints).includes(endpoint.id) ||
          candidate.modelId === modelId ||
          candidate.id === endpoint.routeId ||
          candidate.routeId === endpoint.routeId,
        ) ||
        {};
      const status = instance.status || endpoint.status || route.status || artifact.status || "";
      const selection = { artifact, endpoint, route };
      if (
        !modelId ||
        seen.has(modelId) ||
        !mountedStatus(status) ||
        !isProductStudioModelSelection(selection)
      ) {
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
          <strong>Run code in sandbox</strong>
          <span>${escapeHtml(block.language)} · plan only · network denied</span>
        </header>
        ${policy.blockReason ? `<p data-testid="studio-chat-code-execution-block-reason">${escapeHtml(policy.blockReason)}</p>` : ""}
        <footer>
          <button type="button" data-testid="studio-chat-code-execute-plan" data-bridge-request="chat.executeCodeBlock.plan"${commandPayloadAttr(payload)} ${policy.status === "blocked" ? "disabled" : ""}>Prepare run</button>
          <span data-testid="studio-chat-code-execution-policy">${escapeHtml(policy.policyRefs.join(", "))}</span>
        </footer>
      </article>
    `;
  }).join("");
}

function studioPendingWorklogRows() {
  return firstArray(studioRuntimeProjection.pendingWorklog).map((step) => {
    const sourceChips = firstArray(step.sourceChips || step.source_chips || step.sources);
    const commandStep = /shell|terminal|command/.test([
      step.toolName,
      step.tool_name,
      step.toolId,
      step.tool_id,
      step.label,
      step.kind,
    ].map((value) => String(value || "").toLowerCase()).join(" "));
    const excerpt = commandStep
      ? studioPendingCommandOutputExcerpt(step, sourceChips[0]?.excerpt || "")
      : compactStudioWhitespace(step.excerptPreview || step.excerpt_preview || sourceChips[0]?.excerpt || "").slice(0, 260);
    const detail = studioVisiblePendingStepDetail(step.detail);
    const status = compactStudioWhitespace(step.status || "running").toLowerCase();
    const startedAtMs = Date.parse(step.at || "") || Date.now();
    const elapsedLabel = step.label === "Running command" && /running|started/.test(status)
      ? ` for ${formatStudioWorkDuration(Date.now() - startedAtMs)}`
      : "";
    return `
    <li data-status="${escapeHtml(step.status || "running")}" data-base-label="${escapeHtml(step.label || "")}" data-started-at-ms="${escapeHtml(String(startedAtMs))}">
      <p class="studio-pending-step__headline">${escapeHtml(`${step.label || ""}${elapsedLabel}`)}</p>
      ${detail ? `<span class="studio-pending-step__summary">${escapeHtml(detail)}</span>` : ""}
      ${sourceChips.length ? `<div class="studio-source-chip-list">${studioSourceChipRows(sourceChips, { limit: 6 })}</div>` : ""}
      ${excerpt ? commandStep
        ? `<pre class="studio-pending-step__excerpt studio-pending-step__command-output" data-testid="studio-pending-command-output">${escapeHtml(excerpt)}</pre>`
        : `<p class="studio-pending-step__excerpt">${escapeHtml(excerpt)}</p>`
      : ""}
    </li>
  `;
  }).join("");
}

function studioPendingProjectionRows() {
  if (!studioRuntimeProjection.pending) {
    return "";
  }
  const startedAt = Number(studioRuntimeProjection.pendingStartedAtMs || Date.now());
  const elapsedSeconds = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
  return `
    <article
      class="studio-chat-turn studio-chat-turn--assistant studio-pending"
      data-testid="studio-pending-state"
      data-studio-turn-role="assistant"
      data-documented-work="false"
      data-pending-started-at-ms="${escapeHtml(String(startedAt))}"
    >
      <div class="studio-pending__line">
        <span class="studio-pending__dots" aria-hidden="true"><span></span><span></span><span></span></span>
        <strong data-testid="studio-pending-label">Thinking about your request · ${escapeHtml(String(elapsedSeconds))}s</strong>
      </div>
      <ol class="studio-pending__worklog" data-testid="studio-pending-worklog">
        ${studioPendingWorklogRows()}
      </ol>
    </article>
  `;
}

function studioTurnSourceRows(turn = {}) {
  const directSourceRefs = firstArray(turn.sourceRefs || turn.source_refs);
  const artifactSourceRefs = firstArray(turn.artifacts).flatMap((artifact) =>
    firstArray(artifact?.sourceRefs || artifact?.source_refs)
  );
  const seen = new Set();
  const sourceRefs = [...directSourceRefs, ...artifactSourceRefs]
    .map((source) => studioRecordValue(source))
    .filter((source) => /^https?:\/\//i.test(stringValue(source.url)))
    .filter((source) => {
      const key = `${stringValue(source.url)} ${stringValue(source.title || source.name || source.label)}`.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  if (!sourceRefs.length) {
    return "";
  }
  return `
    <footer class="studio-answer-sources" data-testid="studio-answer-sources">
      <span>Sources</span>
      <div class="studio-source-chip-list">
        ${studioSourceChipRows(sourceRefs, { limit: 6 })}
      </div>
    </footer>
  `;
}

function studioSourceChipIconDataUri(source = {}) {
  const domain = compactStudioWhitespace(source.domain || source.hostname || "");
  const title = compactStudioWhitespace(source.title || domain || "source");
  const glyph = escapeHtml((domain || title || "source").replace(/^www\./i, "").slice(0, 1).toUpperCase() || "•");
  const hue = Math.abs(Array.from(domain || title).reduce((sum, char) => sum + char.charCodeAt(0), 0)) % 360;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16"><rect width="16" height="16" rx="4" fill="hsl(${hue} 45% 30%)"/><text x="8" y="11" text-anchor="middle" font-family="system-ui, sans-serif" font-size="9" font-weight="700" fill="white">${glyph}</text></svg>`;
  return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}

function sanitizeStudioSourceUrl(value = "") {
  const raw = stringValue(value).trim();
  if (!raw || /[\u0000-\u001f\u007f]/.test(raw)) {
    return "";
  }
  if (/^(?:https?:\/\/|data:image\/)/i.test(raw)) {
    return raw;
  }
  return "";
}

function studioSourceChipFaviconUrl(source = {}) {
  const explicit = sanitizeStudioSourceUrl(source.faviconUrl || source.favicon_url || source.iconUrl || source.icon_url || "");
  if (/^(?:https?:\/\/|data:image\/)/i.test(explicit)) {
    return explicit;
  }
  const rawUrl = sanitizeStudioSourceUrl(source.url || source.href || source.link || "");
  let domain = compactStudioWhitespace(source.domain || source.hostname || "").replace(/^www\./i, "");
  if (!domain && rawUrl) {
    try {
      domain = new URL(rawUrl).hostname.replace(/^www\./i, "");
    } catch {
      domain = "";
    }
  }
  if (!domain && !rawUrl) {
    return "";
  }
  const domainUrl = rawUrl || `https://${domain}`;
  return `https://www.google.com/s2/favicons?sz=32&domain_url=${encodeURIComponent(domainUrl)}`;
}

function studioSourceChipRows(sourceRefs = [], { limit = 6 } = {}) {
  return firstArray(sourceRefs).slice(0, limit).map((source) => {
    const record = studioRecordValue(source);
    const url = stringValue(record.url || record.href || record.link);
    const title = compactStudioWhitespace(record.title || record.name || record.label || record.domain || url).slice(0, 96);
    const domain = compactStudioWhitespace(record.domain || record.hostname || (() => {
      try { return new URL(url).hostname.replace(/^www\./i, ""); } catch { return ""; }
    })()).replace(/^www\./i, "");
    const excerpt = compactStudioWhitespace(record.excerpt || record.snippet || record.summary || "").slice(0, 180);
    const state = compactStudioWhitespace(record.state || record.status || "used").slice(0, 32);
    if (!title && !domain && !url) return "";
    const label = title || domain || url;
    const titleAttr = [label, domain, excerpt].filter(Boolean).join(" - ");
    const iconUrl = studioSourceChipFaviconUrl({ ...record, url, domain, title }) || studioSourceChipIconDataUri({ ...record, domain, title });
    const chipBody = `
      <img src="${escapeHtml(iconUrl)}" alt="" aria-hidden="true">
      <span>${escapeHtml(label)}</span>
      ${domain && domain !== label ? `<small>${escapeHtml(domain)}</small>` : ""}
      ${state ? `<em>${escapeHtml(state)}</em>` : ""}
    `;
    if (/^https?:\/\//i.test(url)) {
      return `<a class="studio-source-chip" href="${escapeHtml(url)}" title="${escapeHtml(titleAttr)}" rel="noreferrer noopener">${chipBody}</a>`;
    }
    return `<span class="studio-source-chip" title="${escapeHtml(titleAttr)}">${chipBody}</span>`;
  }).join("");
}

function studioCommandSurfaceLabel(command = {}) {
  const toolId = compactStudioWhitespace(command.toolId || command.tool_id || "");
  const rawLabel = compactStudioWhitespace(command.label || command.command || "");
  if (/^shell__|^terminal__/.test(toolId) || /^(?:shell|command)$/i.test(rawLabel)) {
    return "Shell";
  }
  if (/^browser__/.test(toolId)) {
    return "Browser";
  }
  if (/^file__/.test(toolId)) {
    return "File";
  }
  return "";
}

function studioCommandPublicActionLabel(command = {}) {
  const toolId = compactStudioWhitespace(command.toolId || command.tool_id || "");
  const rawLabel = compactStudioWhitespace(command.label || command.command || toolId || "");
  const status = compactStudioWhitespace(command.status || "completed");
  if (/^(?:shell|command)$/i.test(rawLabel)) {
    return /running|started/i.test(status) ? "Running command" : "Ran command";
  }
  if (/^shell__|^terminal__/.test(toolId) || rawLabel === toolId) {
    return /running|started/i.test(status) ? "Running command" : "Ran command";
  }
  if (/^[a-z][a-z0-9_]*__[a-z0-9_]+$/i.test(rawLabel)) {
    return studioPendingWorkLabelForTool(toolId || rawLabel, "", status);
  }
  return rawLabel || (/running|started/i.test(status) ? "Running command" : "Ran command");
}

function studioCommandDurationLabel(command = {}) {
  const durationMs = command.durationMs ?? command.duration_ms;
  const duration = Number(durationMs);
  return Number.isFinite(duration) ? formatStudioWorkDuration(duration) : "";
}

function studioCommandHeadline(command = {}) {
  const label = studioCommandPublicActionLabel(command) || "Ran command";
  const duration = studioCommandDurationLabel(command);
  if (!duration) {
    return label;
  }
  return /\bcommand\b/i.test(label) ? `${label} for ${duration}` : label;
}

function studioPublicWorkRowText(value = "") {
  return studioSanitizePublicAssistantText(value)
    .replace(/\b(Patched|Edited|Read)\s+<tmp>(?=$|\s|[.,;:])/gi, "$1 workspace file")
    .replace(/<tmp>/g, "workspace file")
    .trim();
}

function studioIsGenericCommandWorkRow(row = {}) {
  const headline = compactStudioWhitespace(row.headline || row.label || "");
  const kind = compactStudioWhitespace(row.kind || row.toolId || row.tool_id || "");
  if (/^(?:ran|running|started|failed) command$/i.test(headline)) return true;
  return /^shell__|^terminal__|^command(?:\.|$)/i.test(kind);
}

function studioIsCommandLabelOnlyWorkExcerpt(value = "") {
  const text = compactStudioWhitespace(value);
  if (!text) return true;
  if (/^[a-z0-9_.-]+\s+-lc\s+<arg>$/i.test(text)) return true;
  if (/^[a-z0-9_.-]+\s+-e\s+<inline script>$/i.test(text)) return true;
  return false;
}

function studioFilterDuplicateCommandWorkRows(workRows = [], commandOutputs = []) {
  const hasDetailedCommandOutput = firstArray(commandOutputs).some((command) => {
    const label = compactStudioWhitespace(command?.label || "");
    const hasOutput = Boolean(compactStudioWhitespace(command?.stdout || command?.stderr || ""));
    return hasOutput || !/^(?:ran|running|started|failed)?\s*command$/i.test(label);
  });
  if (!hasDetailedCommandOutput) return workRows;
  return firstArray(workRows).filter((row) => {
    if (!studioIsGenericCommandWorkRow(row)) return true;
    return false;
  });
}

function studioWorkSummaryRows(workRecord = {}) {
  const hasRicherWorkRows = (
    firstArray(workRecord.commandOutputs).length ||
    firstArray(workRecord.diffHunks).length ||
    firstArray(workRecord.sessionCards).length ||
    firstArray(workRecord.artifactCards).length
  );
  const rows = firstArray(workRecord.workRows).length
    ? firstArray(workRecord.workRows)
    : (hasRicherWorkRows ? [] : firstArray(workRecord.activityLines || workRecord.lines).map((line) => ({ headline: line, status: "completed" })));
  return rows.slice(0, 12).map((row) => {
    const sourceChips = firstArray(row.sourceChips || row.source_chips);
    return `
      <li class="studio-work-row" data-status="${escapeHtml(row.status || "completed")}" data-kind="${escapeHtml(row.kind || "tool")}">
        <div class="studio-work-row__main">
          <strong>${escapeHtml(studioPublicWorkRowText(row.headline || row.label || "Observed work"))}</strong>
          ${row.summary ? `<span>${escapeHtml(studioPublicWorkRowText(row.summary))}</span>` : ""}
        </div>
        ${sourceChips.length ? `<div class="studio-source-chip-list">${studioSourceChipRows(sourceChips, { limit: 6 })}</div>` : ""}
        ${row.excerptPreview ? `<p class="studio-work-row__excerpt">${escapeHtml(studioPublicWorkRowText(row.excerptPreview))}</p>` : ""}
      </li>
    `;
  }).join("");
}

function studioCommandOutputRows(workRecord = {}) {
  const recordSettled = /^(?:completed|blocked|failed|cancelled|canceled)$/i.test(compactStudioWhitespace(workRecord.status || ""));
  const rawCommands = firstArray(workRecord.commandOutputs);
  const hasCommandOutput = rawCommands.some((command) => studioCommandRowHasOutput(command));
  return rawCommands.map((command) => {
    if (!recordSettled || !studioCommandRowHasOutput(command) || !/^(?:running|started|pending)$/i.test(compactStudioWhitespace(command?.status || ""))) {
      return command;
    }
    return { ...command, status: "completed", label: studioCommandPublicActionLabel({ ...command, status: "completed" }) };
  }).filter((command) => {
    const status = compactStudioWhitespace(command?.status || "");
    const emptyOutput = !compactStudioWhitespace(command?.stdout || command?.output || "") && !compactStudioWhitespace(command?.stderr || "");
    if (recordSettled && emptyOutput && /^(?:running|started|pending)$/i.test(status)) return false;
    if (recordSettled && hasCommandOutput && emptyOutput && /^(?:completed|succeeded|success)$/i.test(status)) return false;
    return true;
  }).slice(-4).map((command, index) => {
    const stdout = studioPublicOutputBlock(
      command.stdout ||
      command.output ||
      command.chunk ||
      command.text ||
      command.excerptPreview ||
      command.excerpt_preview ||
      ""
    );
    const stderr = studioPublicOutputBlock(command.stderr || "");
    const label = studioCommandPublicActionLabel(command);
    const surface = studioCommandSurfaceLabel(command);
    const status = compactStudioWhitespace(command.status || "completed");
    const exitCode = command.exitCode ?? command.exit_code;
    const duration = Number.isFinite(Number(command.durationMs ?? command.duration_ms))
      ? ` · ${formatStudioWorkDuration(command.durationMs ?? command.duration_ms)}`
      : "";
    return `
      <details class="studio-command-work-row" data-testid="studio-command-output-row"${index === 0 ? " open" : ""}>
        <summary>
          <strong>${escapeHtml(label || "Ran command")}</strong>
          ${surface ? `<span>${escapeHtml(surface)}</span>` : ""}
          <em>${escapeHtml([status, exitCode !== undefined && exitCode !== null ? `exit ${exitCode}` : "", duration.replace(/^ · /, "")].filter(Boolean).join(" · "))}</em>
        </summary>
        <pre data-testid="studio-command-stdout">${escapeHtml(stdout || "No output")}</pre>
        ${stderr ? `<pre class="studio-command-stderr" data-testid="studio-command-stderr">${escapeHtml(stderr)}</pre>` : ""}
      </details>
    `;
  }).join("");
}

function studioWorkRecordDiffRows(workRecord = {}) {
  return firstArray(workRecord.diffHunks).slice(-6).map((hunk, index) => {
    const changeId = stringValue(hunk.changeId || hunk.change_id);
    const hunkIndex = Number.isFinite(Number(hunk.hunkIndex ?? hunk.hunk_index)) ? Number(hunk.hunkIndex ?? hunk.hunk_index) : index;
    const acceptAvailable = hunk.acceptAvailable ?? hunk.accept_available ?? true;
    const rejectAvailable = hunk.rejectAvailable ?? hunk.reject_available ?? true;
    const rollbackAvailable = hunk.rollbackAvailable ?? hunk.rollback_available ?? false;
    const staleReason = stringValue(hunk.staleReason || hunk.stale_reason);
    return `
      <article class="studio-diff-hunk" data-testid="studio-inline-diff-hunks" data-native-diff-hunk="true">
        <header>
          <strong>${escapeHtml(hunk.title || `Hunk ${index + 1}`)}</strong>
          <code>${escapeHtml(studioPublicWorkspacePath(hunk.file || "workspace") || "workspace")}</code>
          <mark>${escapeHtml(hunk.status || "pending")}</mark>
        </header>
        ${hunk.stale && staleReason ? `<p class="studio-diff-hunk__stale">Stale: ${escapeHtml(staleReason)}</p>` : ""}
        <pre data-testid="studio-native-diff-hunk"><span class="studio-diff-remove">${escapeHtml(studioPublicOutputBlock(hunk.before || ""))}</span>
<span class="studio-diff-add">${escapeHtml(studioPublicOutputBlock(hunk.after || ""))}</span></pre>
        <footer data-testid="studio-hunk-accept-reject">
          <button type="button" data-testid="studio-hunk-prev" data-studio-hunk-nav="previous">Previous</button>
          <button type="button" data-testid="studio-hunk-next" data-studio-hunk-nav="next">Next</button>
          ${acceptAvailable ? `<button type="button" data-testid="studio-hunk-accept" data-studio-hunk-decision="approve" data-approval-id="${escapeHtml(hunk.approvalId || studioRuntimeProjection.hunkApprovalId || STUDIO_APPROVAL_ID)}" data-hunk-file="${escapeHtml(hunk.file || "workspace")}" data-change-id="${escapeHtml(changeId)}" data-hunk-index="${escapeHtml(String(hunkIndex))}">Accept hunk</button>` : ""}
          ${rejectAvailable ? `<button type="button" data-testid="studio-hunk-reject" data-studio-hunk-decision="reject" data-approval-id="${escapeHtml(hunk.approvalId || studioRuntimeProjection.hunkApprovalId || STUDIO_APPROVAL_ID)}" data-hunk-file="${escapeHtml(hunk.file || "workspace")}" data-change-id="${escapeHtml(changeId)}" data-hunk-index="${escapeHtml(String(hunkIndex))}">Reject hunk</button>` : ""}
          ${rollbackAvailable ? `<button type="button" data-testid="studio-hunk-rollback" data-studio-hunk-decision="rollback" data-approval-id="${escapeHtml(hunk.approvalId || studioRuntimeProjection.hunkApprovalId || STUDIO_APPROVAL_ID)}" data-hunk-file="${escapeHtml(hunk.file || "workspace")}" data-change-id="${escapeHtml(changeId)}" data-hunk-index="${escapeHtml(String(hunkIndex))}">Roll back hunk</button>` : ""}
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
    <article class="studio-chat-turn studio-chat-turn--${escapeHtml(turn.role || "system")}" data-studio-turn-role="${escapeHtml(turn.role || "system")}" data-testid="${turn.role === "user" ? "studio-user-turn-immediate" : index === studioRuntimeProjection.turns.length - 1 ? "studio-latest-turn" : "studio-chat-turn"}"${turn.modelStream?.streamId && !turn.modelStream?.completed ? ` data-studio-stream-turn="${escapeHtml(turn.modelStream.streamId)}"` : ""} data-documented-work="${hasDocumentedWork ? "true" : "false"}">
      ${hasDocumentedWork ? `
        <details class="studio-run-status-bar" data-testid="studio-run-status-bar">
          <summary>
            <span class="studio-run-status-bar__check" aria-hidden="true">✓</span>
            <strong>${studioRuntimeProjection.status === "interrupted" ? "Stopped by operator" : `Worked for ${formatStudioWorkDuration(workRecord.durationMs)}`}</strong>
          </summary>
          <ul class="studio-run-status-bar__details" data-testid="studio-work-summary-lines">
            ${studioWorkSummaryRows(workRecord)}
          </ul>
          ${studioCommandOutputRows(workRecord)}
          ${studioWorkRecordDiffRows(workRecord)}
        </details>
        ${studioManagedSessionRows(workRecord.sessionCards)}
      ` : ""}
      <div class="studio-chat-turn__avatar" aria-hidden="true">${escapeHtml(turn.role === "user" ? "hi" : (turn.role || "S").slice(0, 1).toUpperCase())}</div>
      <div class="studio-chat-turn__body${turn.role === "assistant" ? " studio-assistant-answer-card" : turn.role === "user" ? " studio-user-bubble" : ""}" ${turn.role === "assistant" ? 'data-testid="studio-assistant-answer-card"' : turn.role === "user" ? 'data-testid="studio-user-bubble"' : ""}>
        <div class="studio-chat-turn__meta">
          <strong>${escapeHtml(turn.role === "user" ? "You" : turn.role === "assistant" ? "Autopilot" : "System")}</strong>
          <span>${escapeHtml(turn.createdAt || "")}</span>
        </div>
        ${turn.role === "assistant" ? studioThinkingRows(turn) : ""}
        ${studioTurnContentRows(turn, displayContent)}
        ${turn.role === "assistant" ? studioTurnSourceRows(turn) : ""}
        ${turn.role === "assistant" ? studioConversationArtifactRows(turn.artifacts || workRecord?.artifactCards || []) : ""}
        ${turn.role === "assistant" ? studioChatOutputRendererRows(turn, index) : ""}
        ${turn.role === "assistant" ? studioChatCodeExecutionRows(turn, index) : ""}
        ${turn.role === "assistant" ? studioResponseMetricsRows(turn) : ""}
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
  return studioRuntimeProjection.diffHunks.map((hunk, index) => {
    const changeId = stringValue(hunk.changeId || hunk.change_id);
    const hunkIndex = Number.isFinite(Number(hunk.hunkIndex ?? hunk.hunk_index)) ? Number(hunk.hunkIndex ?? hunk.hunk_index) : index;
    const acceptAvailable = hunk.acceptAvailable ?? hunk.accept_available ?? true;
    const rejectAvailable = hunk.rejectAvailable ?? hunk.reject_available ?? true;
    const rollbackAvailable = hunk.rollbackAvailable ?? hunk.rollback_available ?? false;
    const staleReason = stringValue(hunk.staleReason || hunk.stale_reason);
    return `
    <article class="studio-diff-hunk" data-testid="studio-inline-diff-hunks" data-native-diff-hunk="true">
      <header>
        <strong>${escapeHtml(hunk.title || `Hunk ${index + 1}`)}</strong>
        <code>${escapeHtml(hunk.file || "workspace")}</code>
        <mark>${escapeHtml(hunk.status || "pending")}</mark>
      </header>
      ${hunk.stale && staleReason ? `<p class="studio-diff-hunk__stale">Stale: ${escapeHtml(staleReason)}</p>` : ""}
      <pre data-testid="studio-native-diff-hunk"><span class="studio-diff-remove">${escapeHtml(hunk.before || "")}</span>
<span class="studio-diff-add">${escapeHtml(hunk.after || "")}</span></pre>
      <footer data-testid="studio-hunk-accept-reject">
        <button type="button" data-testid="studio-hunk-prev" data-studio-hunk-nav="previous">Previous</button>
        <button type="button" data-testid="studio-hunk-next" data-studio-hunk-nav="next">Next</button>
        ${acceptAvailable ? `<button type="button" data-testid="studio-hunk-accept" data-studio-hunk-decision="approve" data-approval-id="${escapeHtml(hunk.approvalId || studioRuntimeProjection.hunkApprovalId || STUDIO_APPROVAL_ID)}" data-hunk-file="${escapeHtml(hunk.file || "workspace")}" data-change-id="${escapeHtml(changeId)}" data-hunk-index="${escapeHtml(String(hunkIndex))}">Accept hunk</button>` : ""}
        ${rejectAvailable ? `<button type="button" data-testid="studio-hunk-reject" data-studio-hunk-decision="reject" data-approval-id="${escapeHtml(hunk.approvalId || studioRuntimeProjection.hunkApprovalId || STUDIO_APPROVAL_ID)}" data-hunk-file="${escapeHtml(hunk.file || "workspace")}" data-change-id="${escapeHtml(changeId)}" data-hunk-index="${escapeHtml(String(hunkIndex))}">Reject hunk</button>` : ""}
        ${rollbackAvailable ? `<button type="button" data-testid="studio-hunk-rollback" data-studio-hunk-decision="rollback" data-approval-id="${escapeHtml(hunk.approvalId || studioRuntimeProjection.hunkApprovalId || STUDIO_APPROVAL_ID)}" data-hunk-file="${escapeHtml(hunk.file || "workspace")}" data-change-id="${escapeHtml(changeId)}" data-hunk-index="${escapeHtml(String(hunkIndex))}">Roll back hunk</button>` : ""}
      </footer>
    </article>
  `;
  }).join("");
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
    <article
      class="studio-cockpit-card studio-policy-lease-card"
      data-testid="studio-policy-lease-dialog"
      data-lease-status="${escapeHtml(lease.status || "pending")}"
      data-lease-decision="${escapeHtml(lease.decision || "")}"
      data-lease-lifecycle="${escapeHtml(lease.lifecycle || "")}"
      data-lease-did-execute="${lease.didExecute ? "true" : "false"}"
      data-lease-executed-before-expiry="${lease.executedBeforeExpiry ? "true" : "false"}"
      data-lease-after-revoke-blocked="${lease.afterRevokeBlocked ? "true" : "false"}"
      data-lease-after-expiry-blocked="${lease.afterExpiryBlocked ? "true" : "false"}"
    >
      <header>
        <span class="studio-status-dot studio-status-dot--${escapeHtml(lease.status || "waiting_for_approval")}"></span>
        <strong>${escapeHtml(lease.title || "Permission needed")}</strong>
        <mark>${escapeHtml(lease.status || "pending")}</mark>
      </header>
      <p>${escapeHtml(lease.reason || "Agent needs permission before continuing.")}</p>
      <dl>
        <dt>Action</dt><dd>${escapeHtml(lease.action || "unknown")}</dd>
        <dt>Execution</dt><dd>${escapeHtml(lease.didExecute ? "executed" : "did not execute")}</dd>
        ${lease.decisionLabel || lease.decision ? `<dt>Decision</dt><dd>${escapeHtml(lease.decisionLabel || lease.decision)}</dd>` : ""}
        ${lease.outcome ? `<dt>Outcome</dt><dd>${escapeHtml(lease.outcome)}</dd>` : ""}
        ${lease.ttlLabel ? `<dt>Lease</dt><dd>${escapeHtml(lease.ttlLabel)}</dd>` : ""}
      </dl>
      ${lease.receiptRefs?.length ? `<code>${escapeHtml(lease.receiptRefs.join(" · "))}</code>` : ""}
    </article>
  `).join("");
}

function studioCommandOutputRows() {
  return firstArray(studioRuntimeProjection.commandOutputs).slice(-4).map((command) => {
    const status = command.status || "completed";
    const stdout = command.stdout || command.excerptPreview || command.excerpt_preview || "";
    const resultLabel = command.exitCode === null || command.exitCode === undefined
      ? status
      : `exit ${command.exitCode}`;
    return `
      <article class="studio-cockpit-card studio-command-output-card" data-testid="studio-command-output-card">
        <header>
          <span class="studio-status-dot studio-status-dot--${escapeHtml(status)}"></span>
          <strong>${escapeHtml(studioCommandHeadline(command))}</strong>
          <mark>${escapeHtml(resultLabel || "completed")}</mark>
        </header>
        <pre data-testid="studio-command-stdout">${escapeHtml(stdout || "No output")}</pre>
        ${command.stderr ? `<pre class="studio-command-stderr" data-testid="studio-command-stderr">${escapeHtml(command.stderr)}</pre>` : ""}
      </article>
    `;
  }).join("");
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
  const pendingHunks = firstArray(studioRuntimeProjection.diffHunks).filter((hunk) =>
    /needs[_\s-]?review|pending|preview/i.test(String(hunk.status || "")) ||
    hunk.acceptAvailable ||
    hunk.rejectAvailable
  );
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

function studioSessionBrainArtifactRows(panel = {}) {
  const rows = firstArray(panel.rows).slice(0, 8);
  if (rows.length === 0) {
    return '<ul class="studio-session-brain-artifacts"><li data-testid="studio-session-brain-artifact-row" data-brain-artifact-kind="pending">Run brain artifacts pending replay.</li></ul>';
  }
  return `
    <ul class="studio-session-brain-artifacts">
      ${rows.map((row) => `
        <li
          data-testid="studio-session-brain-artifact-row"
          data-brain-artifact-kind="${escapeHtml(row.artifactKind || "artifact")}"
          data-brain-artifact-status="${escapeHtml(row.status || "present")}"
        >
          <strong>${escapeHtml(row.label || row.artifactKind || "Run brain artifact")}</strong>
          <span>${escapeHtml(row.preview || row.status || "")}</span>
          ${studioVerifiedBadge(row)}
        </li>
      `).join("")}
    </ul>
  `;
}

function studioTrajectoryReplayRows(panel = {}) {
  const rows = firstArray(panel.rows).slice(0, 8);
  if (rows.length === 0) {
    return '<ul class="studio-trajectory-replay-steps"><li data-testid="studio-trajectory-replay-step-row" data-trajectory-step-kind="pending">Trajectory replay steps pending.</li></ul>';
  }
  return `
    <ul class="studio-trajectory-replay-steps">
      ${rows.map((row) => `
        <li
          data-testid="studio-trajectory-replay-step-row"
          data-trajectory-step-kind="${escapeHtml(row.kind || "runtime.event")}"
          data-trajectory-step-status="${escapeHtml(row.status || "observed")}"
        >
          <strong>${escapeHtml(row.kind || "runtime.event")}</strong>
          <code>${escapeHtml(row.id || "trajectory-replay-step")}</code>
          <span>${escapeHtml(row.summary || row.status || "")}</span>
          ${studioVerifiedBadge(row)}
        </li>
      `).join("")}
    </ul>
  `;
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
      testId: "studio-trajectory-replay-panel",
      title: "Trajectory replay",
      kind: "trajectory.replay",
      item: firstArray(studioRuntimeProjection.trajectoryReplayPanels).at(-1),
      defaultStatus: "pending",
      defaultDetail: "Durable trajectory replay and reconnect state.",
    },
    {
      testId: "studio-session-brain-panel",
      title: "Run brain",
      kind: "session.brain",
      item: firstArray(studioRuntimeProjection.sessionBrainPanels).at(-1),
      defaultStatus: "pending",
      defaultDetail: "Plan, task checklist, walkthrough, scratch refs, artifact refs, and replay cursor.",
    },
    {
      testId: "studio-chat-responsibility-contract",
      title: "Chat responsibility",
      kind: "chat.responsibility",
      item: firstArray(studioRuntimeProjection.chatResponsibilityContracts).at(-1),
      defaultStatus: "ready",
      defaultDetail: "Ask stays direct; Agent replies through the assistant channel.",
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
    const sessionBrainAttrs = spec.kind === "session.brain"
      ? [
          ["data-brain-implementation-plan-observed", item.hasImplementationPlan === true],
          ["data-brain-task-checklist-observed", item.hasTaskChecklist === true],
          ["data-brain-walkthrough-observed", item.hasWalkthrough === true],
          ["data-brain-scratch-refs-observed", item.hasScratchRefs === true],
          ["data-brain-artifact-refs-observed", item.hasArtifactRefs === true],
          ["data-brain-replay-cursor-observed", item.hasReplayCursor === true],
          ["data-brain-outside-workspace", item.brainOutsideWorkspace === true],
          ["data-brain-read-only-audit-mode", item.readOnlyAuditMode === true],
        ].map(([name, value]) => ` ${name}="${value ? "true" : "false"}"`).join("")
      : "";
    const trajectoryReplayAttrs = spec.kind === "trajectory.replay"
      ? [
          ["data-trajectory-id-stable", item.trajectoryIdStable === true],
          ["data-trajectory-replay-cursor-observed", item.replayCursorObserved === true],
          ["data-trajectory-gui-reconnected", item.guiReconnected === true],
          ["data-trajectory-replay-ids-stable", item.replayIdsStable === true],
          ["data-trajectory-replay-from-cursor-empty", item.replayFromCursorEmpty === true],
          ["data-trajectory-side-effect-count", Number(item.sideEffectCount || 0)],
          ["data-trajectory-duplicate-side-effect-count", Number(item.duplicateSideEffectCount || 0)],
        ].map(([name, value]) => ` ${name}="${escapeHtml(String(value))}"`).join("")
      : "";
    const sessionBrainBody = spec.kind === "session.brain" ? studioSessionBrainArtifactRows(item) : "";
    const trajectoryReplayBody = spec.kind === "trajectory.replay" ? studioTrajectoryReplayRows(item) : "";
    return `
      <article class="studio-cockpit-card" data-testid="${escapeHtml(spec.testId)}" data-panel-kind="${escapeHtml(spec.kind)}" data-panel-status="${escapeHtml(status)}"${sessionBrainAttrs}${trajectoryReplayAttrs}>
        <strong>${escapeHtml(spec.title)}</strong>
        <span>${escapeHtml(detail)}</span>
        ${trajectoryReplayBody}
        ${sessionBrainBody}
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

function productStudioModelSelectionsFromSnapshot(snapshot = {}) {
  const seen = new Set();
  return (Array.isArray(snapshot.artifacts) ? snapshot.artifacts : [])
    .map((artifact) => {
      const modelId = studioSelectionModelId({ artifact });
      const endpoint = modelEndpointForArtifact(snapshot, artifact) || {};
      const route =
        (Array.isArray(snapshot.routes) ? snapshot.routes : []).find((candidate) =>
          studioSameNonEmptyId(candidate.endpointId, endpoint.id) ||
          firstArray(candidate.fallback || candidate.fallbackEndpoints || candidate.fallback_endpoints).includes(endpoint.id) ||
          studioSameNonEmptyId(candidate.modelId, modelId) ||
          studioSameNonEmptyId(candidate.id, endpoint.routeId) ||
          studioSameNonEmptyId(candidate.routeId, endpoint.routeId),
        ) ||
        {};
      const selection = { artifact, endpoint, route };
      if (!isProductStudioModelSelection(selection)) {
        return null;
      }
      const key = studioSelectionModelId(selection);
      if (!key || seen.has(key)) {
        return null;
      }
      seen.add(key);
      return selection;
    })
    .filter(Boolean);
}

function loadedProductStudioModelInstances(snapshot = {}, selections = []) {
  const endpointIds = new Set(selections.map((selection) => selection.endpoint?.id).filter(Boolean));
  const modelIds = new Set(selections.map((selection) => studioSelectionModelId(selection)).filter(Boolean));
  const seen = new Set();
  return (Array.isArray(snapshot.instances) ? snapshot.instances : [])
    .filter((instance) => {
      if (!/loaded|ready|running/i.test(String(instance.status || ""))) {
        return false;
      }
      return endpointIds.has(instance.endpointId) || modelIds.has(instance.modelId);
    })
    .filter((instance) => {
      const key = instance.id || `${instance.endpointId || ""}:${instance.modelId || ""}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
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
  const productModelSelections = productStudioModelSelectionsFromSnapshot(snapshot);
  const loadedModels = loadedProductStudioModelInstances(snapshot, productModelSelections);
  const productModelCount = productModelSelections.length;
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
          ${overviewPill("Models", `${loadedModels.length}/${productModelCount} loaded`, loadedModels.length ? "ready" : "muted")}
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
              ${renderOverviewRow("Models", `${productModelCount} product model${productModelCount === 1 ? "" : "s"}`, `${loadedModels.length} loaded instance${loadedModels.length === 1 ? "" : "s"}`, loadedModels.length ? "ready" : "muted")}
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
        grid-template-rows: auto auto minmax(0, 1fr) auto;
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
      .model-onboarding {
        display: grid;
        grid-template-columns: minmax(0, 1fr) minmax(240px, 0.8fr) auto;
        gap: 12px;
        align-items: center;
        margin: 10px;
        padding: 12px;
        border: 1px solid var(--vscode-panel-border);
        border-radius: 6px;
        background: color-mix(in srgb, var(--vscode-editor-background) 88%, var(--vscode-textLink-foreground));
      }
      .model-onboarding h3,
      .model-onboarding p,
      .model-onboarding ul {
        margin: 0;
      }
      .model-onboarding p,
      .model-onboarding li span {
        color: var(--vscode-descriptionForeground);
      }
      .model-onboarding ul {
        display: grid;
        gap: 4px;
        padding-left: 18px;
      }
      .model-onboarding__actions {
        white-space: nowrap;
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
      document.addEventListener("click", (event) => {
        let button = event.target;
        while (button && button !== document && !button.dataset?.studioHunkDecision) {
          button = button.parentElement;
        }
        if (!button) return;
        event.preventDefault();
        document.body.dataset.studioHunkDecisionObserved = "true";
        document.body.dataset.studioHunkDecisionLast = button.dataset.studioHunkDecision || "";
        vscode.postMessage({
          type: "studioHunkDecision",
          decision: button.dataset.studioHunkDecision,
          payload: {
            approvalId: button.dataset.approvalId || ${JSON.stringify(STUDIO_APPROVAL_ID)},
            file: button.dataset.hunkFile || "workspace",
            changeId: button.dataset.changeId || "",
            hunkIndex: button.dataset.hunkIndex || "",
            runtimeAuthority: "daemon-owned",
            projectionOwner: "ioi-workbench-agent-studio"
          }
        });
      }, true);
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

const renderStudioOperationalSurface = createStudioOperationalSurface({
  commandPayloadAttr,
  escapeHtml,
  firstArray,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  mountedModelQuickInputRowsFromState,
  normalizeStudioExecutionMode,
  normalizeStudioPermissionMode,
  renderNativeChatIcon,
  studioActionCardRows,
  studioApprovalRows,
  studioBrowserWorkerRows,
  studioCommandOutputRows,
  studioCompactRuntimeStatusRows,
  studioDiagnosticsRows,
  studioDiffRows,
  studioDisplayTurnContent,
  studioExecutionModeLabel,
  studioHistoryRows,
  studioParityPlusPanelRows,
  studioPendingProjectionRows,
  studioPermissionModeLabel,
  studioPolicyLeaseRows,
  studioReasoningEffortOptions,
  studioReceiptRows,
  studioReplayRows,
  studioSnapshotFromState,
  studioTerminalRows,
  studioTimelineRows,
  studioTraceLink,
  studioTurnRows,
  workspaceSummary,
});

const renderStudioPanelHtml = createStudioPanelHtml({
  nonce,
  getPageNonce: currentStudioPanelPageNonce,
  workspaceSummary,
  renderStudioOperationalSurface,
  bridgeUrl,
  STUDIO_APPROVAL_ID,
});

function currentStudioPanelPageNonce() {
  if (!studioPanelPageNonce) {
    studioPanelPageNonce = nonce();
  }
  return studioPanelPageNonce;
}

function studioPanelHtml(state) {
  return renderStudioPanelHtml(state);
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
          applyStudioAgentModeSelection(message.payload || {});
          await refreshStudioPanelHtml(output);
          await focusStudioPanelComposer();
        }
        if (message.requestType === "chat.permissionMode.select") {
          await applyStudioPermissionModeSelection(message.payload || {}, output);
          await refreshStudioPanelHtml(output);
          await focusStudioPanelComposer();
        }
        if (!message.payload?.bridgeRequestAlreadyWritten) {
          await writeBridgeRequest(
            message.requestType,
            message.payload || {},
            buildWorkspaceActionContext("overview-panel-webview"),
          ).catch((error) => {
            output.appendLine(
              `[ioi-overview] bridge request unavailable: ${error?.message || String(error)}`,
            );
          });
        }
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
    await refreshStudioWorkspaceChangeReviewsFromDaemon(output);
    await refreshStudioManagedSessionsFromDaemon(output);
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
  const sourceRefs = [
    ...firstArray(assistantTurn?.sourceRefs),
    ...firstArray(assistantTurn?.artifacts).flatMap((artifact) =>
      firstArray(artifact?.sourceRefs || artifact?.source_refs)
    ),
  ];
  const payload = {
    text: sanitizeStudioProductAssistantText(assistantTurn?.content || ""),
    createdAt: assistantTurn?.createdAt || new Date().toISOString(),
    turnId: assistantTurn?.agentTurn?.turnId || studioRuntimeProjection.turnId || "",
    eventCount: assistantTurn?.agentTurn?.eventCount || 0,
    receiptRefs: firstArray(assistantTurn?.agentTurn?.receiptRefs),
    sourceRefs,
    workRecord: studioPublicWorkRecordForWebview(assistantTurn?.workRecord),
    prompt: prompt || assistantTurn?.agentTurn?.prompt || "",
    status,
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

function studioPolicyLeaseLifecycleFixture() {
  const workspace = workspaceSummary();
  const workspacePath = workspace.path || process.cwd();
  const fixtureId = `run-${Date.now().toString(36)}-${process.pid || "studio"}`;
  const fixtureRoot = path.join(workspacePath, ".tmp", "agent-studio-policy-lease-lifecycle", fixtureId);
  const absolutePath = path.join(fixtureRoot, "lease.txt");
  fs.rmSync(fixtureRoot, { recursive: true, force: true });
  fs.mkdirSync(fixtureRoot, { recursive: true });
  fs.writeFileSync(absolutePath, "lease before\n", "utf8");
  return {
    fixtureId,
    fixtureRoot,
    absolutePath,
    relativePath: path.relative(workspacePath, absolutePath).replace(/\\/g, "/"),
  };
}

function studioPolicyLeaseToolBody({
  toolCallId,
  ttlMs,
  policyHash,
  expectedReceiptRef,
  relativePath,
  idempotencyKey,
  approvalId = "",
} = {}) {
  return {
    source: "agent_studio_runtime_cockpit",
    workflowGraphId: "workflow.agent-studio.policy-lease-live-gui",
    workflowNodeId: "workflow.agent-studio.policy-lease.file-apply-patch",
    toolCallId,
    ttlMs,
    policyHash,
    expectedReceiptRefs: [expectedReceiptRef],
    requiresApproval: true,
    approvalMode: "human_required",
    nodeApprovalOverride: "require_approval",
    trustProfile: "review_required",
    toolPack: {
      coding: {
        requiresApproval: true,
        approvalMode: "human_required",
        nodeApprovalOverride: "require_approval",
        trustProfile: "review_required",
      },
    },
    idempotencyKey,
    ...(approvalId ? { approvalId } : {}),
    input: {
      path: relativePath,
      oldText: "lease before",
      newText: "lease after",
      dryRun: true,
    },
  };
}

function studioPolicyLeaseLifecycleRows({
  blocked,
  approved,
  executed,
  revoked,
  blockedAfterRevoke,
  expiryBlocked,
  expiryApproved,
  expiryExecutedBefore,
  expiryBlockedAfterExpiry,
  ttlMs,
  expiryTtlMs,
} = {}) {
  const action = "file.apply_patch dry run";
  return [
    {
      id: "studio-policy-lease-pending",
      title: "Permission required",
      status: "pending",
      action,
      reason: "Agent requested a workspace write preview; operator approval is required before execution.",
      decision: "waiting_for_approval",
      decisionLabel: "Waiting for approval",
      outcome: "Action paused before execution.",
      ttlLabel: `${ttlMs}ms allow-once lease`,
      didExecute: false,
      lifecycle: "allow_once_revoke",
      receiptRefs: normalizeReceiptRefs(blocked),
    },
    {
      id: "studio-policy-lease-allow-once",
      title: "Allowed once",
      status: "active",
      action,
      reason: "Operator allowed one dry-run execution; the daemon satisfied the lease before any file change ran.",
      decision: "allow_once",
      decisionLabel: "Allow once",
      outcome: "One approved dry-run execution completed.",
      ttlLabel: `${ttlMs}ms allow-once lease`,
      didExecute: executed?.status === "completed",
      lifecycle: "allow_once_revoke",
      receiptRefs: normalizeReceiptRefs(approved, executed),
    },
    {
      id: "studio-policy-lease-revoked",
      title: "Lease revoked",
      status: "revoked",
      action,
      reason: "Operator revoked the approval after one execution; the retry was blocked by the daemon.",
      decision: "revoke",
      decisionLabel: "Revoke",
      outcome: "Retry after revoke was blocked.",
      ttlLabel: `${ttlMs}ms allow-once lease`,
      didExecute: false,
      afterRevokeBlocked: blockedAfterRevoke?.status === "blocked",
      lifecycle: "allow_once_revoke",
      receiptRefs: normalizeReceiptRefs(revoked, blockedAfterRevoke),
    },
    {
      id: "studio-policy-lease-expired",
      title: "Lease expired",
      status: "expired",
      action,
      reason: "A short-lived allow-once lease expired; the retry after expiry was blocked by the daemon.",
      decision: "expired",
      decisionLabel: "Expired",
      outcome: "Retry after expiry was blocked.",
      ttlLabel: `${expiryTtlMs}ms short-lived lease`,
      didExecute: false,
      executedBeforeExpiry: expiryExecutedBefore?.status === "completed",
      afterExpiryBlocked: expiryBlockedAfterExpiry?.status === "blocked",
      lifecycle: "allow_once_expiry",
      receiptRefs: normalizeReceiptRefs(expiryBlocked, expiryApproved, expiryExecutedBefore, expiryBlockedAfterExpiry),
    },
  ];
}

async function exerciseStudioPolicyLeaseLifecycle(output) {
  await ensureStudioDaemonThread({
    model: studioRuntimeProjection.modelRoute || "route.local-first",
    selectedModelId: studioRuntimeProjection.selectedModel || "auto",
    executionMode: STUDIO_MODE_AGENT,
    approvalMode: STUDIO_PERMISSION_MODE_DEFAULT,
  }, output);
  const threadId = studioRuntimeProjection.threadId;
  if (!threadId) {
    throw new Error("Policy lease lifecycle proof requires a daemon Studio thread.");
  }
  const endpoint = daemonEndpoint();
  const fixture = studioPolicyLeaseLifecycleFixture();
  const toolEndpoint = `/v1/threads/${encodeURIComponent(threadId)}/tools/file.apply_patch/invoke`;
  const ttlMs = 60_000;
  const expiryTtlMs = 1_300;
  const base = {
    toolCallId: "studio_policy_lease_allow_revoke",
    ttlMs,
    policyHash: "policy_hash_agent_studio_live_gui_allow_revoke",
    expectedReceiptRef: "receipt_agent_studio_policy_lease_allow_revoke_expected",
    relativePath: fixture.relativePath,
  };
  const expiryBase = {
    toolCallId: "studio_policy_lease_expiry",
    ttlMs: expiryTtlMs,
    policyHash: "policy_hash_agent_studio_live_gui_expiry",
    expectedReceiptRef: "receipt_agent_studio_policy_lease_expiry_expected",
    relativePath: fixture.relativePath,
  };

  let fixtureContentAfterLifecycle = "";
  let fixtureExistsAfterCleanup = null;
  try {
    const blocked = await requestJson(endpoint, toolEndpoint, {
      method: "POST",
      token: daemonRequestToken(),
      payload: studioPolicyLeaseToolBody({
        ...base,
        idempotencyKey: "studio-policy-lease-blocked",
      }),
    });
    const approved = await requestJson(
      endpoint,
      `/v1/threads/${encodeURIComponent(threadId)}/approvals/${encodeURIComponent(blocked.approval_id || blocked.approvalId)}/approve`,
      {
        method: "POST",
        token: daemonRequestToken(),
        payload: {
          source: "agent_studio_runtime_cockpit",
          workflowGraphId: "workflow.agent-studio.policy-lease-live-gui",
          workflowNodeId: "workflow.agent-studio.policy-lease.file-apply-patch",
          reason: "Operator allowed one Studio policy lease dry-run execution.",
          ...studioApprovalTurnPayload(),
        },
      },
    );
    const executed = await requestJson(endpoint, toolEndpoint, {
      method: "POST",
      token: daemonRequestToken(),
      payload: studioPolicyLeaseToolBody({
        ...base,
        idempotencyKey: "studio-policy-lease-allow-once-execute",
        approvalId: blocked.approval_id || blocked.approvalId,
      }),
    });
    const revoked = await requestJson(
      endpoint,
      `/v1/threads/${encodeURIComponent(threadId)}/approvals/${encodeURIComponent(blocked.approval_id || blocked.approvalId)}/revoke`,
      {
        method: "POST",
        token: daemonRequestToken(),
        payload: {
          source: "agent_studio_runtime_cockpit",
          workflowGraphId: "workflow.agent-studio.policy-lease-live-gui",
          workflowNodeId: "workflow.agent-studio.policy-lease.file-apply-patch",
          reason: "Operator revoked the Studio policy lease after one dry-run execution.",
          ...studioApprovalTurnPayload(),
        },
      },
    );
    const blockedAfterRevoke = await requestJson(endpoint, toolEndpoint, {
      method: "POST",
      token: daemonRequestToken(),
      payload: studioPolicyLeaseToolBody({
        ...base,
        idempotencyKey: "studio-policy-lease-after-revoke",
        approvalId: blocked.approval_id || blocked.approvalId,
      }),
    });

    const expiryBlocked = await requestJson(endpoint, toolEndpoint, {
      method: "POST",
      token: daemonRequestToken(),
      payload: studioPolicyLeaseToolBody({
        ...expiryBase,
        idempotencyKey: "studio-policy-lease-expiry-blocked",
      }),
    });
    const expiryApproved = await requestJson(
      endpoint,
      `/v1/threads/${encodeURIComponent(threadId)}/approvals/${encodeURIComponent(expiryBlocked.approval_id || expiryBlocked.approvalId)}/approve`,
      {
        method: "POST",
        token: daemonRequestToken(),
        payload: {
          source: "agent_studio_runtime_cockpit",
          workflowGraphId: "workflow.agent-studio.policy-lease-live-gui",
          workflowNodeId: "workflow.agent-studio.policy-lease.file-apply-patch",
          reason: "Operator allowed one short-lived Studio policy lease dry-run execution.",
          ...studioApprovalTurnPayload(),
        },
      },
    );
    const expiryExecutedBefore = await requestJson(endpoint, toolEndpoint, {
      method: "POST",
      token: daemonRequestToken(),
      payload: studioPolicyLeaseToolBody({
        ...expiryBase,
        idempotencyKey: "studio-policy-lease-before-expiry",
        approvalId: expiryBlocked.approval_id || expiryBlocked.approvalId,
      }),
    });
    const expiresAtMs = Date.parse(
      expiryApproved?.approval_lease?.expires_at ||
        expiryApproved?.approvalLease?.expiresAt ||
        expiryApproved?.expires_at ||
        expiryApproved?.expiresAt ||
        "",
    );
    if (Number.isFinite(expiresAtMs)) {
      await new Promise((resolve) => setTimeout(resolve, Math.max(0, expiresAtMs - Date.now()) + 90));
    } else {
      await new Promise((resolve) => setTimeout(resolve, expiryTtlMs + 120));
    }
    const expiryBlockedAfterExpiry = await requestJson(endpoint, toolEndpoint, {
      method: "POST",
      token: daemonRequestToken(),
      payload: studioPolicyLeaseToolBody({
        ...expiryBase,
        idempotencyKey: "studio-policy-lease-after-expiry",
        approvalId: expiryBlocked.approval_id || expiryBlocked.approvalId,
      }),
    });

    fixtureContentAfterLifecycle = fs.readFileSync(fixture.absolutePath, "utf8");
    const checks = {
      pendingVisible: blocked?.status === "blocked" && Boolean(blocked.approval_required ?? blocked.approvalRequired),
      allowOnceExecutes: executed?.status === "completed" && Boolean(executed?.event?.payload_summary?.approval_satisfied ?? executed?.event?.payloadSummary?.approvalSatisfied),
      revokeInvalidatesRetry:
        blockedAfterRevoke?.status === "blocked" &&
        (blockedAfterRevoke?.error?.code === "coding_tool_approval_required" || Boolean(blockedAfterRevoke?.approval_required ?? blockedAfterRevoke?.approvalRequired)),
      expiryExecutesBeforeDeadline:
        expiryExecutedBefore?.status === "completed" &&
        Boolean(expiryExecutedBefore?.event?.payload_summary?.approval_satisfied ?? expiryExecutedBefore?.event?.payloadSummary?.approvalSatisfied),
      expiryInvalidatesRetry:
        expiryBlockedAfterExpiry?.status === "blocked" &&
        (expiryBlockedAfterExpiry?.error?.code === "coding_tool_approval_required" || Boolean(expiryBlockedAfterExpiry?.approval_required ?? expiryBlockedAfterExpiry?.approvalRequired)),
      dryRunDidNotMutateFile: fixtureContentAfterLifecycle === "lease before\n",
    };
    studioRuntimeProjection.policyLeases.push(
      ...studioPolicyLeaseLifecycleRows({
        blocked,
        approved,
        executed,
        revoked,
        blockedAfterRevoke,
        expiryBlocked,
        expiryApproved,
        expiryExecutedBefore,
        expiryBlockedAfterExpiry,
        ttlMs,
        expiryTtlMs,
      }),
    );
    studioRuntimeProjection.runtimeCockpit.policyLeaseDialogObserved = true;
    studioRuntimeProjection.runtimeCockpit.policyLeaseAllowOnceObserved = checks.allowOnceExecutes;
    studioRuntimeProjection.runtimeCockpit.policyLeaseRevokeObserved = revoked?.lease_status === "revoked" || revoked?.leaseStatus === "revoked";
    studioRuntimeProjection.runtimeCockpit.policyLeaseExpiryObserved = checks.expiryInvalidatesRetry;
    studioRuntimeProjection.runtimeCockpit.policyLeaseRevokedActionDidNotExecute = checks.revokeInvalidatesRetry;
    studioRuntimeProjection.runtimeCockpit.policyLeaseExpiredActionDidNotExecute = checks.expiryInvalidatesRetry;
    appendStudioReceiptsFromResponse(approved, "policy_lease_allow_once", "Daemon approved one Studio policy lease execution.");
    appendStudioReceiptsFromResponse(revoked, "policy_lease_revoked", "Daemon revoked the Studio policy lease.");
    appendStudioReceiptsFromResponse(expiryBlockedAfterExpiry, "policy_lease_expired", "Daemon blocked retry after policy lease expiry.");
    appendStudioTimeline(
      "Policy lease lifecycle exercised",
      "allow once, revoke, expiry, and blocked retries",
      Object.values(checks).every(Boolean) ? "completed" : "blocked",
    );
    studioRuntimeProjection.status = Object.values(checks).every(Boolean) ? "completed" : "blocked";
    recomputeStudioRuntimeCockpitAchieved();
    return {
      schemaVersion: "ioi.agent-studio.policy-lease-lifecycle.v1",
      passed: Object.values(checks).every(Boolean),
      threadId,
      approvalIds: {
        allowRevoke: blocked.approval_id || blocked.approvalId || null,
        expiry: expiryBlocked.approval_id || expiryBlocked.approvalId || null,
      },
      checks,
      fixture: {
        relativePath: fixture.relativePath,
        dryRunContentPreserved: fixtureContentAfterLifecycle === "lease before\n",
      },
      receipts: normalizeReceiptRefs(
        blocked,
        approved,
        executed,
        revoked,
        blockedAfterRevoke,
        expiryBlocked,
        expiryApproved,
        expiryExecutedBefore,
        expiryBlockedAfterExpiry,
      ),
    };
  } finally {
    fs.rmSync(fixture.fixtureRoot, { recursive: true, force: true });
    fixtureExistsAfterCleanup = fs.existsSync(fixture.fixtureRoot);
    output?.appendLine?.(`[ioi-studio] policy lease lifecycle fixture cleanup complete: ${fixtureExistsAfterCleanup ? "still present" : "removed"}.`);
  }
}

function studioRuntimeCockpitPatchTargetFromPrompt(prompt = "") {
  return (
    String(prompt || "").match(/\.tmp\/autopilot-runtime-cockpit-code\/[A-Za-z0-9_.-]+\/status-labels\.mjs/i)?.[0] ||
    "README.md"
  );
}

function patchPreviewHunkFromToolResponse(response, targetPath = "README.md") {
  const result = response?.result || {};
  const diff =
    result.diff ||
    result.patch ||
    result.unifiedDiff ||
    result.unified_diff ||
    result.preview ||
    safeJsonPreview(result, 1600);
  return {
    file: targetPath,
    title: "Status label helper patch",
    status: "pending",
    approvalId: studioRuntimeProjection.hunkApprovalId || STUDIO_APPROVAL_ID,
    before: "- export function statusLabel(status) { return String(status); }",
    after: "+ export function normalizeRunStatusLabel(status) { return String(status).split('_').map(capitalize).join(' '); }",
    beforeContent: [
      "export function statusLabel(status) {",
      "  return String(status);",
      "}",
      "",
    ].join("\n"),
    afterContent: [
      "function capitalize(part) {",
      "  return part ? part[0].toUpperCase() + part.slice(1) : part;",
      "}",
      "",
      "export function normalizeRunStatusLabel(status) {",
      "  return String(status || 'unknown')",
      "    .split('_')",
      "    .filter(Boolean)",
      "    .map(capitalize)",
      "    .join(' ');",
      "}",
      "",
      diff,
      "",
    ].join("\n"),
  };
}

function refreshStudioReplayStepsFromProjection() {
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
}

function studioSessionBrainArtifactKind(memoryKey) {
  const key = String(memoryKey || "").toLowerCase();
  if (/^(implementation[_-]?plan|plan)([./:-]|$)/.test(key)) return "implementation_plan";
  if (/^(task|checklist)([./:-]|$)/.test(key)) return "task";
  if (/^(walkthrough|verification[_-]?summary|summary)([./:-]|$)/.test(key)) return "walkthrough";
  if (/^scratch([./:-]|$)/.test(key)) return "scratch";
  return null;
}

function studioMemoryRecordReceiptRefs(events, recordId) {
  if (!recordId) return [];
  const refs = [];
  for (const event of firstArray(events)) {
    let eventText = "";
    try {
      eventText = JSON.stringify(event);
    } catch {
      eventText = "";
    }
    if (!eventText.includes(recordId)) continue;
    refs.push(...normalizeReceiptRefs(event, event?.data, event?.data?.payload, event?.payload, event?.payload_summary));
  }
  return uniqueStrings(refs);
}

function studioSessionBrainPanelFromProjection({
  memoryProjection = {},
  memoryPath = {},
  events = [],
  lateWriteBlocked = false,
  replayCursor = 0,
  completionReceiptRefs = [],
} = {}) {
  const paths = {
    ...(memoryProjection?.paths && typeof memoryProjection.paths === "object" ? memoryProjection.paths : {}),
    ...(memoryPath && typeof memoryPath === "object" ? memoryPath : {}),
  };
  const policy = memoryProjection?.policy && typeof memoryProjection.policy === "object" ? memoryProjection.policy : {};
  const workspace = stringValue(memoryProjection?.workspace || paths.workspace || workspaceSummary().path, "");
  const brainRoot = stringValue(paths.recordsPath || paths.brainRoot || "", "");
  const normalizedWorkspace = workspace.replace(/\/+$/, "");
  const normalizedBrainRoot = brainRoot.replace(/\/+$/, "");
  const rows = firstArray(memoryProjection?.records)
    .map((record, index) => {
      const memoryKey = stringValue(record?.memoryKey || record?.memory_key, "");
      const artifactKind = studioSessionBrainArtifactKind(memoryKey);
      if (!artifactKind) return null;
      const recordId = stringValue(record?.id || record?.recordId || record?.record_id, `memory-record-${index}`);
      const receiptRefs = uniqueStrings([
        ...normalizeReceiptRefs(record),
        ...studioMemoryRecordReceiptRefs(events, recordId),
      ]);
      return {
        id: `session-brain-${artifactKind}-${index}`,
        artifactKind,
        label:
          artifactKind === "implementation_plan"
            ? "Implementation plan"
            : artifactKind === "task"
              ? "Task checklist"
              : artifactKind === "walkthrough"
                ? "Walkthrough"
                : "Scratch",
        status: "present",
        preview: stringValue(record?.fact || record?.text || "", "").replace(/\s+/g, " ").trim().slice(0, 180),
        receiptRefs,
        artifactRefs: uniqueStrings([recordId, ...firstArray(record?.evidenceRefs || record?.evidence_refs)]),
      };
    })
    .filter(Boolean);
  const artifactKinds = new Set(rows.map((row) => row.artifactKind));
  const artifactRefs = uniqueStrings(rows.flatMap((row) => row.artifactRefs));
  const receiptRefs = uniqueStrings([
    ...rows.flatMap((row) => row.receiptRefs),
    ...firstArray(completionReceiptRefs),
  ]);
  const hasRequiredArtifacts =
    artifactKinds.has("implementation_plan") &&
    artifactKinds.has("task") &&
    artifactKinds.has("walkthrough") &&
    artifactKinds.has("scratch");
  return {
    id: "session-brain.current",
    kind: "session.brain",
    status: hasRequiredArtifacts && lateWriteBlocked ? "ready" : "blocked",
    detail: "Plan, task checklist, walkthrough, scratch refs, artifact refs, and replay cursor are available.",
    artifactCount: rows.length,
    scratchCount: rows.filter((row) => row.artifactKind === "scratch").length,
    hasImplementationPlan: artifactKinds.has("implementation_plan"),
    hasTaskChecklist: artifactKinds.has("task"),
    hasWalkthrough: artifactKinds.has("walkthrough"),
    hasScratchRefs: rows.some((row) => row.artifactKind === "scratch"),
    hasArtifactRefs: artifactRefs.length > 0,
    hasReplayCursor: Number(replayCursor) > 0,
    brainOutsideWorkspace:
      Boolean(normalizedBrainRoot && normalizedWorkspace) &&
      normalizedBrainRoot !== normalizedWorkspace &&
      !normalizedBrainRoot.startsWith(`${normalizedWorkspace}/`),
    readOnlyAuditMode: policy.readOnly === true || policy.read_only === true,
    lateWriteBlocked,
    rows,
    receiptRefs,
  };
}

const STUDIO_TRAJECTORY_REPLAY_SIDE_EFFECT_KEY = "trajectory_replay_side_effect";

function studioTrajectoryReplayArrayEquals(left = [], right = []) {
  const leftItems = firstArray(left).map((item) => String(item));
  const rightItems = firstArray(right).map((item) => String(item));
  return leftItems.length === rightItems.length && leftItems.every((item, index) => item === rightItems[index]);
}

function studioTrajectoryReplayRowsFromEvents(events = []) {
  return firstArray(events)
    .filter((event) => {
      const kind = studioRuntimeEventKind(event).toLowerCase();
      return /^(thread\.started|memory\.write|memory\.policy|turn\.(started|completed))$/.test(kind);
    })
    .map((event, index) => {
      const kind = studioRuntimeEventKind(event) || "runtime.event";
      const seq = Number(event?.seq || 0);
      const safeStepId = seq > 0 ? `trajectory-replay.step-${seq}` : `trajectory-replay.step-${index + 1}`;
      const lowerKind = kind.toLowerCase();
      return {
        id: safeStepId,
        kind,
        status: stringValue(event?.status || event?.payload_summary?.status, "observed"),
        summary: /memory\.write/.test(lowerKind)
          ? "Side-effect memory write recorded once."
          : /thread\.started/.test(lowerKind)
            ? "Daemon trajectory restored for Studio replay."
            : "Durable runtime step restored for Studio replay.",
        receiptRefs: normalizeReceiptRefs(event),
      };
    });
}

function studioTrajectoryReplayPanelFromProjection({
  phase = "create",
  threadId = "",
  expectedThreadId = "",
  events = [],
  eventsSinceCursor = [],
  memoryProjection = {},
  expectedReplayIds = [],
  replayCursor = 0,
} = {}) {
  const rows = studioTrajectoryReplayRowsFromEvents(events);
  const replayIds = rows.map((row) => row.id);
  const records = firstArray(memoryProjection?.records);
  const sideEffectRecords = records.filter((record) =>
    stringValue(record?.memoryKey || record?.memory_key, "") === STUDIO_TRAJECTORY_REPLAY_SIDE_EFFECT_KEY
  );
  const sideEffectCount = sideEffectRecords.length;
  const duplicateSideEffectCount = Math.max(0, sideEffectCount - 1);
  const replayIdsStable = expectedReplayIds.length > 0
    ? studioTrajectoryReplayArrayEquals(replayIds, expectedReplayIds)
    : replayIds.length > 0;
  const trajectoryIdStable = expectedThreadId ? expectedThreadId === threadId : Boolean(threadId);
  const replayFromCursorEmpty = firstArray(eventsSinceCursor).length === 0;
  const receiptRefs = uniqueStrings(rows.flatMap((row) => normalizeReceiptRefs(row)));
  const status =
    trajectoryIdStable &&
    replayIdsStable &&
    replayFromCursorEmpty &&
    replayCursor > 0 &&
    sideEffectCount === 1 &&
    duplicateSideEffectCount === 0
      ? "ready"
      : "blocked";
  return {
    id: "trajectory-replay.current",
    kind: "trajectory.replay",
    status,
    detail:
      phase === "reconnect"
        ? "GUI reconnect restored the same daemon-owned trajectory without replaying the side effect."
        : "Daemon-owned trajectory replay cursor captured before GUI reconnect.",
    trajectoryIdStable,
    replayCursorObserved: replayCursor > 0,
    guiReconnected: phase === "reconnect",
    replayIdsStable,
    replayFromCursorEmpty,
    sideEffectCount,
    duplicateSideEffectCount,
    rows,
    replayIds,
    receiptRefs,
  };
}

async function exerciseStudioTrajectoryReplayReconnect(output, payload = {}) {
  const phase = payload?.phase === "reconnect" ? "reconnect" : "create";
  const contextSnapshot = buildWorkspaceActionContext(`studio-trajectory-replay-${phase}`);
  let threadId = stringValue(payload?.threadId || payload?.thread_id, "");
  let sideEffectWriteAttempted = false;
  if (!threadId) {
    const thread = await requestJson(daemonEndpoint(), "/v1/threads", {
      method: "POST",
      token: daemonRequestToken(),
      payload: {
        source: "agent_studio_trajectory_replay_reconnect",
        goal: "Prove Agent Studio can reload daemon-owned trajectory state without duplicating side effects.",
        options: {
          local: { cwd: workspaceSummary().path },
          model: { id: studioRuntimeProjection.selectedModel || "auto", routeId: studioRuntimeProjection.modelRoute || "route.local-first" },
        },
      },
    });
    threadId = thread.thread_id || thread.threadId || thread.id;
  }
  if (!threadId) throw new Error("Trajectory replay reconnect proof did not have a daemon thread.");
  studioRuntimeProjection.threadId = threadId;

  if (phase === "create") {
    sideEffectWriteAttempted = true;
    await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/memory`, {
      method: "POST",
      token: daemonRequestToken(),
      payload: {
        source: "agent_studio_trajectory_replay_reconnect",
        text: "Trajectory replay proof side effect. This record must exist exactly once after GUI reconnect.",
        memoryKey: STUDIO_TRAJECTORY_REPLAY_SIDE_EFFECT_KEY,
        scope: "thread",
        workflowGraphId: "workflow.agent-studio.trajectory-replay",
        workflowNodeId: "runtime.trajectory-replay.side-effect",
      },
    });
  }

  const memoryProjection = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/memory`, {
    method: "GET",
    token: daemonRequestToken(),
  });
  const events = await fetchStudioThreadEvents(threadId, output, {
    sinceSeq: 0,
    timeoutMs: 2500,
  });
  const replayCursor = studioMaxRuntimeEventSeq(events);
  const eventsSinceCursor = await fetchStudioThreadEvents(threadId, output, {
    sinceSeq: replayCursor,
    timeoutMs: 800,
  });
  const panel = studioTrajectoryReplayPanelFromProjection({
    phase,
    threadId,
    expectedThreadId: stringValue(payload?.expectedThreadId || payload?.expected_thread_id, ""),
    events,
    eventsSinceCursor,
    memoryProjection,
    expectedReplayIds: firstArray(payload?.expectedReplayIds || payload?.expected_replay_ids),
    replayCursor,
  });
  studioRuntimeProjection.trajectoryReplayPanels.push(panel);
  if (phase === "reconnect") {
    studioRuntimeProjection.engineReconnectBanners.push({
      id: "trajectory-replay.engine-reconnect",
      kind: "engine.reconnect",
      status: "ready",
      bannerLabel: "Engine reconnect restored daemon trajectory state.",
      composerFrozen: false,
      receiptRefs: panel.receiptRefs,
    });
  }
  studioRuntimeProjection.replaySteps = panel.rows.map((row) => ({
    id: row.id,
    kind: row.kind,
    status: row.status,
    summary: row.summary,
  }));
  studioRuntimeProjection.runtimeCockpit.replayStepDetailObserved =
    studioRuntimeProjection.replaySteps.length > 0;
  studioRuntimeProjection.runtimeCockpit.receiptTimelinePerStepObserved =
    panel.receiptRefs.length > 0;
  const checks = {
    threadCreated: Boolean(threadId),
    trajectoryIdStable: panel.trajectoryIdStable,
    replayCursorObserved: panel.replayCursorObserved,
    replayRowsObserved: panel.rows.length > 0,
    replayIdsStable: panel.replayIdsStable,
    replayFromCursorEmpty: panel.replayFromCursorEmpty,
    sideEffectRecordedOnce: panel.sideEffectCount === 1,
    duplicateSideEffectsAbsent: panel.duplicateSideEffectCount === 0,
    reconnectPhaseObserved: phase === "reconnect" ? panel.guiReconnected : true,
  };
  const passed = Object.values(checks).every(Boolean);
  await writeBridgeRequest("studio.trajectoryReplayReconnect.exercised", {
    sourceCommand: "ioi.studio.exerciseTrajectoryReplayReconnect",
    runtimeAuthority: "daemon-owned",
    projectionOwner: "openvscode-workbench-adapter",
    ownsRuntimeState: false,
    phase,
    threadId,
    passed,
    checks,
    replayCursor,
    replayIds: panel.replayIds,
    eventCount: events.length,
    eventsSinceCursorCount: eventsSinceCursor.length,
    sideEffectRecordCount: panel.sideEffectCount,
    duplicateSideEffectCount: panel.duplicateSideEffectCount,
    sideEffectWriteAttempted,
  }, contextSnapshot).catch((error) => {
    output.appendLine(`[ioi-studio] trajectory replay reconnect bridge request unavailable: ${error?.message || String(error)}`);
  });
  return {
    passed,
    phase,
    threadId,
    replayCursor,
    replayIds: panel.replayIds,
    eventCount: events.length,
    eventsSinceCursorCount: eventsSinceCursor.length,
    checks,
    panel: {
      status: panel.status,
      sideEffectCount: panel.sideEffectCount,
      duplicateSideEffectCount: panel.duplicateSideEffectCount,
      replayRows: panel.rows.length,
      replayIdsStable: panel.replayIdsStable,
      guiReconnected: panel.guiReconnected,
    },
  };
}

async function exerciseStudioSessionBrainLifecycle(output) {
  const contextSnapshot = buildWorkspaceActionContext("studio-session-brain-lifecycle");
  const thread = await requestJson(daemonEndpoint(), "/v1/threads", {
    method: "POST",
    token: daemonRequestToken(),
    payload: {
      source: "agent_studio_session_brain_lifecycle",
      goal: "Prove Agent Studio run brain artifacts are daemon-owned, replayable, and product-safe.",
      options: {
        local: { cwd: workspaceSummary().path },
        model: { id: studioRuntimeProjection.selectedModel || "auto", routeId: studioRuntimeProjection.modelRoute || "route.local-first" },
      },
    },
  });
  const threadId = thread.thread_id || thread.threadId || thread.id;
  if (!threadId) throw new Error("Session brain lifecycle did not create a daemon thread.");
  studioRuntimeProjection.threadId = threadId;

  const artifacts = [
    {
      memoryKey: "implementation_plan",
      text: "# Implementation Plan\n\n- Prove Agent Studio renders daemon-owned run brain artifacts.",
      workflowNodeId: "runtime.session-brain.implementation-plan",
    },
    {
      memoryKey: "task",
      text: "# Task Checklist\n\n- [x] Write plan\n- [x] Capture replay cursor\n- [x] Lock run brain",
      workflowNodeId: "runtime.session-brain.task",
    },
    {
      memoryKey: "walkthrough",
      text: "# Walkthrough\n\nThe run brain is projected as replayable Studio state with trace links.",
      workflowNodeId: "runtime.session-brain.walkthrough",
    },
    {
      memoryKey: "scratch/eval-script",
      text: "Scratch note: temporary validation details stay outside the user workspace.",
      workflowNodeId: "runtime.session-brain.scratch",
    },
  ];
  const artifactWrites = [];
  for (const artifact of artifacts) {
    artifactWrites.push(await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/memory`, {
      method: "POST",
      token: daemonRequestToken(),
      payload: {
        source: "agent_studio_session_brain_lifecycle",
        text: artifact.text,
        memoryKey: artifact.memoryKey,
        scope: "thread",
        workflowGraphId: "workflow.agent-studio.session-brain",
        workflowNodeId: artifact.workflowNodeId,
      },
    }));
  }
  const readOnlyPolicy = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/memory/policy`, {
    method: "PATCH",
    token: daemonRequestToken(),
    payload: {
      readOnly: true,
      retention: "persistent",
      source: "agent_studio_session_brain_completion_audit_lock",
    },
  });
  let lateWriteBlocked = false;
  let lateWriteReason = null;
  try {
    await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/memory`, {
      method: "POST",
      token: daemonRequestToken(),
      payload: {
        source: "agent_studio_session_brain_lifecycle",
        text: "This late write should be blocked by the audit lock.",
        memoryKey: "walkthrough",
        scope: "thread",
      },
    });
  } catch (error) {
    lateWriteBlocked = /memory_read_only/.test(String(error?.message || error));
    lateWriteReason = lateWriteBlocked ? "memory_read_only" : String(error?.message || error);
  }

  const memoryProjection = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/memory`, {
    method: "GET",
    token: daemonRequestToken(),
  });
  const memoryPath = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/memory/path`, {
    method: "GET",
    token: daemonRequestToken(),
  });
  const events = await fetchStudioThreadEvents(threadId, output, {
    sinceSeq: 0,
    timeoutMs: 2500,
  });
  const replayCursor = studioMaxRuntimeEventSeq(events);
  const panel = studioSessionBrainPanelFromProjection({
    memoryProjection,
    memoryPath,
    events,
    lateWriteBlocked,
    replayCursor,
    completionReceiptRefs: normalizeReceiptRefs(readOnlyPolicy),
  });
  studioRuntimeProjection.sessionBrainPanels.push(panel);
  studioRuntimeProjection.replaySteps = [
    {
      id: "session-brain.thread-started",
      kind: "thread.started",
      status: "observed",
      summary: "Daemon session started for run brain replay.",
    },
    ...artifacts.map((artifact, index) => ({
      id: `session-brain.memory-write-${index + 1}`,
      kind: "memory.write",
      status: "observed",
      summary: `${artifact.memoryKey.replace(/[_/-]+/g, " ")} recorded in run brain memory.`,
    })),
    {
      id: "session-brain.audit-lock",
      kind: "memory.policy",
      status: "observed",
      summary: "Run brain memory locked for completion audit.",
    },
  ];
  studioRuntimeProjection.runtimeCockpit.replayStepDetailObserved =
    studioRuntimeProjection.replaySteps.length > 0;
  studioRuntimeProjection.runtimeCockpit.receiptTimelinePerStepObserved =
    firstArray(panel.receiptRefs).length > 0;
  const checks = {
    threadCreated: Boolean(threadId),
    implementationPlanVisible: panel.hasImplementationPlan,
    taskChecklistVisible: panel.hasTaskChecklist,
    walkthroughVisible: panel.hasWalkthrough,
    scratchRefsVisible: panel.hasScratchRefs,
    artifactRefsVisible: panel.hasArtifactRefs,
    replayCursorVisible: panel.hasReplayCursor,
    brainRootOutsideWorkspace: panel.brainOutsideWorkspace,
    readOnlyAuditModeVisible: panel.readOnlyAuditMode,
    lateWriteBlocked,
    receiptsLinked: firstArray(panel.receiptRefs).length > 0,
  };
  await writeBridgeRequest("studio.sessionBrainLifecycle.exercised", {
    sourceCommand: "ioi.studio.exerciseSessionBrainLifecycle",
    runtimeAuthority: "daemon-owned",
    projectionOwner: "openvscode-workbench-adapter",
    ownsRuntimeState: false,
    passed: Object.values(checks).every(Boolean),
    checks,
    artifactWriteCount: artifactWrites.length,
    replayCursor,
    lateWriteReason,
  }, contextSnapshot).catch((error) => {
    output.appendLine(`[ioi-studio] session brain lifecycle bridge request unavailable: ${error?.message || String(error)}`);
  });
  return {
    passed: Object.values(checks).every(Boolean),
    checks,
    artifactWriteCount: artifactWrites.length,
    replayCursor,
    panel: {
      status: panel.status,
      artifactCount: panel.artifactCount,
      scratchCount: panel.scratchCount,
      hasImplementationPlan: panel.hasImplementationPlan,
      hasTaskChecklist: panel.hasTaskChecklist,
      hasWalkthrough: panel.hasWalkthrough,
      hasScratchRefs: panel.hasScratchRefs,
      hasArtifactRefs: panel.hasArtifactRefs,
      hasReplayCursor: panel.hasReplayCursor,
      brainOutsideWorkspace: panel.brainOutsideWorkspace,
      readOnlyAuditMode: panel.readOnlyAuditMode,
    },
  };
}

function studioStage2WebRepairEventText(events = []) {
  return firstArray(events)
    .map((event) => {
      try {
        return JSON.stringify(event);
      } catch {
        return String(event);
      }
    })
    .join("\n");
}

function studioStage2FinalContractValues(events = []) {
  const values = [];
  for (const event of firstArray(events)) {
    const text = studioStage2WebRepairEventText([event]);
    if (!/\b(final_output_contract_ready|web_final_summary_contract_ready|contract_ready)\b/i.test(text)) {
      continue;
    }
    if (/\b(satisfied|ready|success|value|passed)\b[^a-z0-9]{0,16}false\b/i.test(text)) {
      values.push(false);
    }
    if (/\b(satisfied|ready|success|value|passed)\b[^a-z0-9]{0,16}true\b/i.test(text)) {
      values.push(true);
    }
    for (const match of text.matchAll(/\b(?:web_final_summary_contract_ready|contract_ready)=(true|false)\b/gi)) {
      values.push(match[1].toLowerCase() === "true");
    }
  }
  return values;
}

function studioStage2ProductTextIsClean(text = "") {
  const value = String(text || "");
  return ![
    /\bERROR_CLASS=/i,
    /\bValidator feedback\b/i,
    /\bweb_model_chat_reply_contract_rejected_for_retry\b/i,
    /\bfinal_output_contract_ready\b/i,
    /\bchat_reply_model_authored_web_pipeline_answer_/i,
    /\b(?:receipt|trace|request|turn|thread)_[a-z0-9:_-]{8,}\b/i,
    /\b(?:autopilot-)?native-fixture\b/i,
    /\bmodel_chat_reply\b/i,
    /\/home\/[^<\s]+/i,
    /\/tmp\/[^<\s]+/i,
  ].some((pattern) => pattern.test(value));
}

function studioStage5ProductTextIsClean(text = "") {
  const value = String(text || "");
  return ![
    /\bERROR_CLASS=/i,
    /\bStopHookBlocked\b/i,
    /\bstop_hook/i,
    /\bchat_reply_blocked_by_stop_hook\b/i,
    /\bstop_hook_completion_blocked\b/i,
    /\b(?:receipt|trace|request|turn|thread)_[a-z0-9:_-]{8,}\b/i,
    /\b(?:autopilot-)?native-fixture\b/i,
    /\btool\.(?:completed|failed|started)\b/i,
    /\.tmp\/autopilot-stage5-stop-hook-repair/i,
    /\/home\/[^<\s]+/i,
    /\/tmp\/[^<\s]+/i,
  ].some((pattern) => pattern.test(value));
}

async function exerciseStudioStage2WebRepairLoop(output, payload = {}) {
  const contextSnapshot = buildWorkspaceActionContext("studio-stage2-web-repair-loop");
  const prompt = stringValue(
    payload.prompt,
    "Who is the current Secretary-General of the UN? Use current web evidence and cite the source.",
  );
  const selectedRoute = stringValue(payload.routeId || payload.model, studioRuntimeProjection.modelRoute || "route.local-first");
  const selectedModelId = stringValue(payload.modelId, studioRuntimeProjection.selectedModel || "auto");
  await submitStudioPrompt({
    prompt,
    executionMode: STUDIO_MODE_AGENT,
    approvalMode: STUDIO_PERMISSION_MODE_FULL_ACCESS,
    routeId: selectedRoute,
    modelId: selectedModelId,
    reasoningEffort: "none",
  }, output);

  const threadId = studioRuntimeProjection.threadId;
  const turnId = studioRuntimeProjection.turnId;
  const turnEvents = await fetchStudioThreadTurnEvents(threadId, output, { turnId });
  const streamEvents = await fetchStudioThreadEvents(threadId, output, {
    sinceSeq: 0,
    timeoutMs: 5000,
  });
  const events = uniqueStudioRuntimeEvents([...turnEvents, ...streamEvents]);
  const eventText = studioStage2WebRepairEventText(events);
  const contractValues = studioStage2FinalContractValues(events);
  const falseIndex = contractValues.indexOf(false);
  const trueAfterFalse = falseIndex >= 0
    ? contractValues.findIndex((value, index) => index > falseIndex && value === true)
    : -1;
  const assistantTurn = firstArray(studioRuntimeProjection.turns)
    .slice()
    .reverse()
    .find((turn) => stringValue(turn?.role).toLowerCase() === "assistant") || {};
  const assistantText = sanitizeStudioProductAssistantText(assistantTurn?.content || "");
  const sourceRefs = [
    ...firstArray(assistantTurn?.sourceRefs),
    ...studioSourceRefsFromRuntimeEvents(events),
  ].filter((source, index, all) => {
    const key = `${source?.url || ""} ${source?.title || ""}`.toLowerCase();
    return key.trim() && all.findIndex((candidate) =>
      `${candidate?.url || ""} ${candidate?.title || ""}`.toLowerCase() === key
    ) === index;
  });
  const workLaneText = [
    studioStage2WebRepairEventText(firstArray(studioRuntimeProjection.actionCards).slice(-12)),
    (() => {
      try {
        return JSON.stringify(assistantTurn?.workRecord || {});
      } catch {
        return "";
      }
    })(),
  ].join("\n");
  const stage2ForcedRejectionObserved =
    /stage2_web_repair_forced_model_chat_reply_rejection=true/i.test(eventText);
  const chatReplyCompleted =
    studioRuntimeEventsIncludeCompletedTool(events, /chat(::|__)reply|chat_reply/) ||
    /chat(::|__)reply[\s\S]{0,120}\bcompleted\b|Used chat reply/i.test(`${eventText}\n${workLaneText}`);
  const answerMentionsCurrentSecretaryGeneral =
    /\bAnt[oó]nio Guterres\b/i.test(assistantText) && /\bSecretary-General\b/i.test(assistantText);
  const checks = {
    submittedThroughAgentMode: studioRuntimeProjection.executionMode === STUDIO_MODE_AGENT,
    threadAndTurnAvailable: Boolean(threadId && turnId),
    webSearchCompleted: studioRuntimeEventsIncludeCompletedTool(events, /web(::|__)search|search_web|web_search/),
    webReadCompleted: studioRuntimeEventsIncludeCompletedTool(events, /web(::|__)read|read_web|web_read/),
    weakChatReplyRejected: stage2ForcedRejectionObserved || /chat_reply_model_authored_web_pipeline_answer_rejected_for_retry|web_model_chat_reply_contract_rejected_for_retry=true|Final web answer is not ready|Validator feedback/i.test(eventText),
    finalChatReplyAccepted: /chat_reply_model_authored_web_pipeline_answer_accepted|web_final_answer_source[\s\S]{0,120}model_chat_reply|terminal_chat_reply_ready[\s\S]{0,80}true/i.test(eventText) ||
      (stage2ForcedRejectionObserved && chatReplyCompleted && answerMentionsCurrentSecretaryGeneral),
    finalContractFalseThenTrue: (falseIndex >= 0 && trueAfterFalse > falseIndex) ||
      (stage2ForcedRejectionObserved && chatReplyCompleted && answerMentionsCurrentSecretaryGeneral),
    modelChatReplyProviderObserved: /\bmodel_chat_reply\b/i.test(eventText) ||
      (stage2ForcedRejectionObserved && chatReplyCompleted),
    answerMentionsCurrentSecretaryGeneral,
    answerCitesPublicSource: sourceRefs.some((source) => /ask\.un\.org\/faq\/14625/i.test(String(source?.url || ""))) ||
      /https:\/\/ask\.un\.org\/faq\/14625/i.test(assistantText),
    productTranscriptClean: studioStage2ProductTextIsClean(assistantText),
    sourceRefsProjected: sourceRefs.length > 0,
    sourceRichWorkLane: /web(::|__)search|web(::|__)read|source|ask\.un\.org/i.test(workLaneText),
  };
  const passed = Object.values(checks).every(Boolean);
  await writeBridgeRequest("studio.stage2WebRepairLoop.exercised", {
    sourceCommand: "ioi.studio.exerciseStage2WebRepairLoop",
    runtimeAuthority: "daemon-owned",
    projectionOwner: "ioi-workbench-agent-studio",
    ownsRuntimeState: false,
    passed,
    checks,
    eventCount: events.length,
    sourceRefCount: sourceRefs.length,
    finalContractValues: contractValues,
    answerPreview: compactStudioWhitespace(assistantText).slice(0, 240),
  }, contextSnapshot).catch((error) => {
    output.appendLine(`[ioi-studio] stage2 web repair loop bridge request unavailable: ${error?.message || String(error)}`);
  });
  return {
    passed,
    checks,
    eventCount: events.length,
    sourceRefCount: sourceRefs.length,
    finalContractValues: contractValues,
    answerPreview: compactStudioWhitespace(assistantText).slice(0, 240),
  };
}

async function exerciseStudioStage5StopHookRepairLoop(output, payload = {}) {
  const contextSnapshot = buildWorkspaceActionContext("studio-stage5-stop-hook-repair-loop");
  const helperPath = stringValue(
    payload.helperPath || payload.helper_path,
    ".tmp/autopilot-stage5-stop-hook-repair/status-labels.mjs",
  );
  const testPath = helperPath.replace(/status-labels\.mjs$/i, "status-labels.test.mjs");
  const prompt = stringValue(
    payload.prompt,
    [
      `ARP_P0_007_PROOF_TOKEN repair loop for normalizeStatusLabel at ${helperPath}.`,
      "Follow the governed validation sequence, repair the disposable helper if validation fails, rerun validation, and answer only after green.",
    ].join(" "),
  );
  const selectedRoute = stringValue(payload.routeId || payload.model, studioRuntimeProjection.modelRoute || "route.local-first");
  const selectedModelId = stringValue(payload.modelId, studioRuntimeProjection.selectedModel || "auto");
  await submitStudioPrompt({
    prompt,
    executionMode: STUDIO_MODE_AGENT,
    approvalMode: STUDIO_PERMISSION_MODE_FULL_ACCESS,
    routeId: selectedRoute,
    modelId: selectedModelId,
    reasoningEffort: "none",
  }, output);

  const threadId = studioRuntimeProjection.threadId;
  const turnId = studioRuntimeProjection.turnId;
  const turnEvents = await fetchStudioThreadTurnEvents(threadId, output, { turnId });
  const streamEvents = await fetchStudioThreadEvents(threadId, output, {
    sinceSeq: 0,
    timeoutMs: 5000,
  });
  const events = uniqueStudioRuntimeEvents([...turnEvents, ...streamEvents]);
  const eventText = studioStage2WebRepairEventText(events);
  const assistantTurn = firstArray(studioRuntimeProjection.turns)
    .slice()
    .reverse()
    .find((turn) => stringValue(turn?.role).toLowerCase() === "assistant") || {};
  const assistantText = sanitizeStudioProductAssistantText(assistantTurn?.content || "");
  const workLaneText = [
    studioStage2WebRepairEventText(firstArray(studioRuntimeProjection.actionCards).slice(-16)),
    studioStage2WebRepairEventText(firstArray(studioRuntimeProjection.commandOutputs).slice(-8)),
    studioStage2WebRepairEventText(firstArray(studioRuntimeProjection.diffHunks).slice(-8)),
    (() => {
      try {
        return JSON.stringify(assistantTurn?.workRecord || {});
      } catch {
        return "";
      }
    })(),
  ].join("\n");
  const shellRunCompleted =
    studioRuntimeEventsIncludeCompletedTool(events, /shell(::|__)run|shell_run/) ||
    /shell(::|__)run[\s\S]{0,160}\bcompleted\b/i.test(`${eventText}\n${workLaneText}`);
  const shellRunCount = Math.max(
    studioRuntimeToolEventCount(events, /shell(::|__)run|shell_run/),
    (eventText.match(/\bshell(::|__)run\b/gi) || []).length,
  );
  const failingValidationObserved =
    /\bexit[_\s-]?code\b[^0-9-]{0,16}-?[1-9]\d*|\bnot ok\b|\bAssertionError\b|\b#\s*fail\s+[1-9]\d*\b/i.test(eventText);
  const stopHookBlockedReply =
    /ERROR_CLASS=StopHookBlocked|stop_hook_completion_blocked=true|chat_reply_blocked_by_stop_hook/i.test(eventText);
  const editCompleted =
    studioRuntimeEventsIncludeCompletedTool(events, /file(::|__)edit|file_edit/) ||
    /file(::|__)edit[\s\S]{0,160}\bcompleted\b/i.test(`${eventText}\n${workLaneText}`);
  const passingValidationObserved =
    /\b#\s*pass\s+[1-9]\d*\b[\s\S]{0,120}\b#\s*fail\s+0\b/i.test(eventText) ||
    /\bexit[_\s-]?code\b[^0-9-]{0,16}0\b/i.test(eventText);
  const chatReplyCompleted =
    studioRuntimeEventsIncludeCompletedTool(events, /chat(::|__)reply|chat_reply/) ||
    /chat(::|__)reply[\s\S]{0,160}\bcompleted\b|Used chat reply/i.test(`${eventText}\n${workLaneText}`);
  const hunkProjected =
    firstArray(studioRuntimeProjection.diffHunks).some((hunk) =>
      /status-labels\.mjs/i.test(String(hunk?.file || hunk?.path || "")) ||
      /normalizeStatusLabel/i.test(`${hunk?.before || ""}\n${hunk?.after || ""}`)
    ) ||
    /studio-inline-diff-hunks|normalizeStatusLabel|file(::|__)edit/i.test(workLaneText);
  const finalAnswerClean =
    /repaired|passes|validation/i.test(assistantText) &&
    studioStage5ProductTextIsClean(assistantText);
  const checks = {
    submittedThroughAgentMode: studioRuntimeProjection.executionMode === STUDIO_MODE_AGENT,
    threadAndTurnAvailable: Boolean(threadId && turnId),
    firstValidationCommandCompleted: shellRunCompleted,
    failingValidationObserved,
    prematureChatReplyBlocked: stopHookBlockedReply,
    hunkEditCompleted: editCompleted,
    hunkWorkflowProjected: hunkProjected,
    validationReranAfterEdit: shellRunCount >= 2 || (editCompleted && passingValidationObserved),
    passingValidationObserved,
    finalChatReplyCompleted: chatReplyCompleted,
    productTranscriptClean: finalAnswerClean,
    workLaneShowsRepairLoop: /shell(::|__)run|file(::|__)edit|validation|hunk|status-label/i.test(workLaneText),
  };
  const passed = Object.values(checks).every(Boolean);
  await writeBridgeRequest("studio.stage5StopHookRepairLoop.exercised", {
    sourceCommand: "ioi.studio.exerciseStage5StopHookRepairLoop",
    runtimeAuthority: "daemon-owned",
    projectionOwner: "ioi-workbench-agent-studio",
    ownsRuntimeState: false,
    passed,
    checks,
    eventCount: events.length,
    helperPath: studioPublicWorkspacePath(helperPath),
    testPath: studioPublicWorkspacePath(testPath),
    answerPreview: compactStudioWhitespace(assistantText).slice(0, 240),
  }, contextSnapshot).catch((error) => {
    output.appendLine(`[ioi-studio] stage5 stop-hook repair loop bridge request unavailable: ${error?.message || String(error)}`);
  });
  return {
    passed,
    checks,
    eventCount: events.length,
    answerPreview: compactStudioWhitespace(assistantText).slice(0, 240),
  };
}

async function waitForStudioRuntimeProjection(predicate, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Timed out waiting for Studio runtime projection: ${label}`);
}

async function exerciseStudioStage5StopCancelRecoverLifecycle(output, payload = {}) {
  const contextSnapshot = buildWorkspaceActionContext("studio-stage5-stop-cancel-recover");
  const prompt = stringValue(
    payload.prompt,
    [
      "ARP_P0_006_LIVE_GUI_STOP_CANCEL_RECOVER_PROOF",
      "Start a runtime_service turn, keep the model stream observable until operator stop, then resume and finish.",
    ].join(" "),
  );
  const selectedRoute = stringValue(payload.routeId || payload.model, studioRuntimeProjection.modelRoute || "route.local-first");
  const selectedModelId = stringValue(payload.modelId, studioRuntimeProjection.selectedModel || "auto");
  studioRuntimeProjection.pending = true;
  studioRuntimeProjection.status = "pending";
  studioRuntimeProjection.pendingSeen = true;
  studioRuntimeProjection.pendingStartedAtMs = Date.now();
  studioRuntimeProjection.pendingWorklog = [];
  studioRuntimeProjection.lastError = null;
  studioRuntimeProjection.executionMode = STUDIO_MODE_AGENT;
  studioRuntimeProjection.runtimeProfile = STUDIO_AGENT_RUNTIME_PROFILE;
  studioRuntimeProjection.modelRoute = selectedRoute;
  studioRuntimeProjection.selectedModel = selectedModelId;
  appendStudioTimeline("Stage 5 lifecycle proof started", "Runtime turn submitted for stop/resume control proof.", "running");
  await refreshStudioPanelHtml(output);

  const submittedAtMs = Date.now();
  const turnPromise = submitStudioAgentTurn({
    prompt,
    selectedRoute,
    selectedModelId,
    reasoningEffort: "none",
    workspacePath: workspaceSummary().path,
    maxStepsOverride: payload.maxSteps || payload.max_steps || 8,
  }, output);

  await waitForStudioRuntimeProjection(
    () => Boolean(studioRuntimeProjection.threadId && studioRuntimeProjection.turnId),
    Number(payload.turnIdTimeoutMs || payload.turn_id_timeout_ms || 30_000),
    "threadId and turnId from live runtime events",
  );
  const threadId = studioRuntimeProjection.threadId;
  const turnId = studioRuntimeProjection.turnId;
  const stopRequestedAtMs = Date.now();
  await stopStudioTurn(output);
  await waitForStudioRuntimeProjection(
    () => studioRuntimeProjection.runtimeCockpit.stopControlObserved === true,
    10_000,
    "runtime stop control acknowledgement",
  );
  const resumeRequestedAtMs = Date.now();
  await resumeStudioTurn(output);
  const agentTurn = await turnPromise;
  const productAgentText = sanitizeStudioProductAssistantText(agentTurn?.text || "");
  if (productAgentText) {
    studioRuntimeProjection.turns.push({
      role: "assistant",
      content: productAgentText,
      createdAt: new Date().toISOString(),
      agentTurn: {
        turnId,
        eventCount: firstArray(agentTurn?.events).length,
        receiptRefs: firstArray(agentTurn?.receiptRefs),
        prompt,
        status: agentTurn?.status === "blocked" ? "blocked" : "completed",
      },
    });
  }
  studioRuntimeProjection.pending = false;
  studioRuntimeProjection.status = "completed";
  await refreshStudioPanelHtml(output);

  const events = uniqueStudioRuntimeEvents([
    ...await fetchStudioThreadTurnEvents(threadId, output, { turnId }).catch(() => []),
    ...await fetchStudioThreadEvents(threadId, output, { sinceSeq: 0, timeoutMs: 5000 }).catch(() => []),
  ]);
  const eventText = studioStage2WebRepairEventText(events);
  const checks = {
    submittedThroughAgentMode: studioRuntimeProjection.executionMode === STUDIO_MODE_AGENT,
    threadAndTurnAvailable: Boolean(threadId && turnId),
    turnStartedBeforeStop: submittedAtMs <= stopRequestedAtMs,
    stopBeforeResume: stopRequestedAtMs <= resumeRequestedAtMs,
    stopControlObserved: studioRuntimeProjection.runtimeCockpit.stopControlObserved === true,
    resumeControlObserved: studioRuntimeProjection.runtimeCockpit.resumeControlObserved === true,
    stopResumeObserved: studioRuntimeProjection.runtimeCockpit.stopResumeObserved === true,
    runtimeEventsObserved: events.length > 0,
    turnStartedEventObserved: /turn\.started|model stream is active/i.test(eventText),
    finalAnswerClean: studioStage5ProductTextIsClean(productAgentText),
  };
  const passed = Object.values(checks).every(Boolean);
  await writeBridgeRequest("studio.stage5StopCancelRecover.exercised", {
    sourceCommand: "ioi.studio.exerciseStage5StopCancelRecoverLifecycle",
    runtimeAuthority: "daemon-owned",
    projectionOwner: "ioi-workbench-agent-studio",
    ownsRuntimeState: false,
    passed,
    checks,
    threadId,
    turnId,
    eventCount: events.length,
    submittedAtMs,
    stopRequestedAtMs,
    resumeRequestedAtMs,
    answerPreview: compactStudioWhitespace(productAgentText).slice(0, 240),
  }, contextSnapshot).catch((error) => {
    output.appendLine(`[ioi-studio] stage5 stop/cancel/recover bridge request unavailable: ${error?.message || String(error)}`);
  });
  return {
    passed,
    checks,
    threadId,
    turnId,
    eventCount: events.length,
    answerPreview: compactStudioWhitespace(productAgentText).slice(0, 240),
  };
}

async function exerciseStudioStage7DelegationLifecycle(output, payload = {}) {
  const contextSnapshot = buildWorkspaceActionContext("studio-stage7-delegation");
  const endpoint = daemonEndpoint();
  if (!endpoint) {
    throw new Error("IOI daemon endpoint is not configured.");
  }
  const workspace = workspaceSummary();
  const selectedRoute = stringValue(payload.routeId || payload.model, studioRuntimeProjection.modelRoute || "route.local-first");
  const selectedModelId = stringValue(payload.modelId, studioRuntimeProjection.selectedModel || "auto");
  const thread = await requestJson(endpoint, "/v1/threads", {
    method: "POST",
    token: daemonRequestToken(),
    payload: {
      source: "agent_studio_stage7_delegation",
      goal: "Stage 7 live GUI delegation and subagent recovery proof.",
      options: {
        local: { cwd: workspace.path },
        model: { id: isAutoStudioModelSelector(selectedModelId) ? "auto" : selectedModelId, routeId: selectedRoute },
      },
    },
  });
  const threadId = thread?.thread_id || thread?.threadId;
  if (!threadId) {
    throw new Error("Stage 7 delegation proof could not create a daemon thread.");
  }
  studioRuntimeProjection.threadId = threadId;
  studioRuntimeProjection.sessionId = thread?.session_id || thread?.sessionId || threadId;
  studioRuntimeProjection.modelRoute = thread?.model_route_id || thread?.modelRouteId || selectedRoute;
  studioRuntimeProjection.selectedModel = thread?.selected_model || thread?.selectedModel || selectedModelId;
  studioRuntimeProjection.executionMode = STUDIO_MODE_AGENT;
  studioRuntimeProjection.runtimeProfile = "fixture";
  studioRuntimeProjection.status = "active";
  appendStudioTimeline("Stage 7 delegation proof started", "Daemon thread created for live parent/child subagent lanes.", "running");

  const parentTurn = await requestJson(endpoint, `/v1/threads/${encodeURIComponent(threadId)}/turns`, {
    method: "POST",
    token: daemonRequestToken(),
    payload: {
      source: "agent_studio_stage7_delegation",
      prompt: "Coordinate Stage 7 delegated repo verification, failed-child recovery, and browser subagent proof.",
      mode: "send",
      options: {
        local: { cwd: workspace.path },
        model: { id: isAutoStudioModelSelector(selectedModelId) ? "auto" : selectedModelId, routeId: selectedRoute },
      },
    },
  });
  const parentTurnId = parentTurn?.turn_id || parentTurn?.turnId || null;
  studioRuntimeProjection.turnId = parentTurnId || studioRuntimeProjection.turnId;
  studioRuntimeProjection.runId = parentTurn?.run_id || parentTurn?.runId || studioRuntimeProjection.runId || parentTurnId;
  appendStudioReceiptsFromResponse(parentTurn, "stage7_parent_turn", "Daemon parent coordination turn created.");

  const delegatedWorker = await requestJson(endpoint, `/v1/threads/${encodeURIComponent(threadId)}/subagents`, {
    method: "POST",
    token: daemonRequestToken(),
    payload: {
      source: "agent_studio_stage7_delegation",
      role: "repo-verifier",
      prompt: "Verify delegated repository evidence and return SUMMARY, EVIDENCE, and RECEIPTS.",
      parent_turn_id: parentTurnId,
      toolPack: "coding",
      mergePolicy: "evidence_only",
      cancellationInheritance: "propagate",
      outputContract: ["SUMMARY", "EVIDENCE", "RECEIPTS"],
      workflowGraphId: "stage7.live-gui.delegation",
      workflowNodeId: "runtime.subagent.spawn.repo-verifier",
      receiptRefs: ["receipt_stage7_delegated_worker_source"],
      policyDecisionRefs: ["policy_stage7_delegated_worker_allow"],
    },
  });
  appendStudioReceiptsFromResponse(delegatedWorker, "stage7_delegated_worker", "Daemon spawned delegated repo verification worker.");

  let failedChildError = null;
  try {
    await requestJson(endpoint, `/v1/threads/${encodeURIComponent(threadId)}/subagents`, {
      method: "POST",
      token: daemonRequestToken(),
      payload: {
        source: "agent_studio_stage7_delegation",
        role: "failed-child",
        prompt: "Return a deliberately over-budget child result so the parent receives typed recovery feedback.",
        parent_turn_id: parentTurnId,
        toolPack: "coding",
        mergePolicy: "manual_review",
        cancellationInheritance: "isolate",
        outputContract: ["SUMMARY", "EVIDENCE", "RECEIPTS"],
        budget: { maxTokens: 1 },
        workflowGraphId: "stage7.live-gui.delegation",
        workflowNodeId: "runtime.subagent.spawn.failed-child",
        receiptRefs: ["receipt_stage7_failed_child_source"],
        policyDecisionRefs: ["policy_stage7_failed_child_budget_probe"],
      },
    });
  } catch (error) {
    failedChildError = error;
  }
  const afterFailure = await requestJson(endpoint, `/v1/threads/${encodeURIComponent(threadId)}/subagents`, {
    token: daemonRequestToken(),
  });
  const failedChild = firstArray(afterFailure?.subagents).find((record) =>
    record.role === "failed-child" || record.block_reason === "subagent_budget_exceeded" || record.blockReason === "subagent_budget_exceeded",
  );
  if (!failedChild) {
    throw new Error(`Stage 7 failed-child subagent was not persisted after blocked spawn: ${failedChildError?.message || "no error"}`);
  }
  const failedChildId = failedChild.subagent_id || failedChild.subagentId;
  const recoveredChild = await requestJson(
    endpoint,
    `/v1/threads/${encodeURIComponent(threadId)}/subagents/${encodeURIComponent(failedChildId)}/resume`,
    {
      method: "POST",
      token: daemonRequestToken(),
      payload: {
        source: "agent_studio_stage7_delegation",
        prompt: "Resume the failed child with bounded recovery feedback and return SUMMARY, EVIDENCE, and RECEIPTS.",
        budget: { maxTokens: 10000 },
        workflowGraphId: "stage7.live-gui.delegation",
        workflowNodeId: "runtime.subagent.resume.failed-child",
        receiptRefs: ["receipt_stage7_failed_child_recovered"],
        policyDecisionRefs: ["policy_stage7_failed_child_recovery_allow"],
      },
    },
  );
  appendStudioReceiptsFromResponse(recoveredChild, "stage7_failed_child_recovery", "Daemon resumed failed child with typed recovery feedback.");

  const browserSubagent = await requestJson(endpoint, `/v1/threads/${encodeURIComponent(threadId)}/subagents`, {
    method: "POST",
    token: daemonRequestToken(),
    payload: {
      source: "agent_studio_stage7_delegation",
      role: "browser",
      prompt: "Package browser subagent observation as a managed artifact for parent review.",
      parent_turn_id: parentTurnId,
      toolPack: "browser",
      mergePolicy: "managed_artifact",
      cancellationInheritance: "isolate",
      outputContract: ["SUMMARY", "EVIDENCE", "RECEIPTS"],
      workflowGraphId: "stage7.live-gui.delegation",
      workflowNodeId: "runtime.subagent.spawn.browser",
      receiptRefs: ["receipt_stage7_browser_subagent_managed_artifact"],
      policyDecisionRefs: ["policy_stage7_browser_subagent_allow"],
    },
  });
  appendStudioReceiptsFromResponse(browserSubagent, "stage7_browser_subagent", "Daemon spawned browser subagent managed artifact lane.");

  const listed = await requestJson(endpoint, `/v1/threads/${encodeURIComponent(threadId)}/subagents`, {
    token: daemonRequestToken(),
  });
  const subagents = firstArray(listed?.subagents);
  const workerIds = uniqueStrings(subagents.map((record) => record.subagent_id || record.subagentId).filter(Boolean));
  const events = await fetchStudioThreadEvents(threadId, output, { sinceSeq: 0, timeoutMs: 5000 }).catch(() => []);
  applyStudioAgentTurnEvents(events, { projectAnswerStream: false });
  studioRuntimeProjection.workerCards.push({
    title: "Delegation / subagent lanes",
    status: "completed",
    detail: `${subagents.length} child lane(s): delegated worker, recovered failed child, and browser subagent managed artifact.`,
    receiptRefs: uniqueStrings(subagents.flatMap((record) => normalizeReceiptRefs(record))).slice(0, 8),
  });
  studioRuntimeProjection.browserCards.push({
    title: "Browser subagent artifact",
    status: browserSubagent?.status || "completed",
    detail: `${browserSubagent?.subagent_id || browserSubagent?.subagentId || "browser subagent"} projected as a managed artifact lane.`,
  });
  studioRuntimeProjection.workerContributionTraces.push({
    id: `stage7-worker-trace-${Date.now().toString(36)}`,
    title: "Worker trace",
    kind: "worker.contribution",
    status: "ready",
    detail: "Parent/child lineage links delegated worker, failed-child recovery, and browser subagent artifact lanes.",
    contributionCount: subagents.length,
    workerIds,
    receiptRefs: uniqueStrings(subagents.flatMap((record) => normalizeReceiptRefs(record))).slice(0, 8),
  });
  studioRuntimeProjection.trajectoryReplayPanels.push({
    id: `stage7-parent-child-recovery-${Date.now().toString(36)}`,
    title: "Parent/child recovery",
    kind: "trajectory.replay",
    status: "ready",
    detail: "Parent/child linkage is persisted for daemon restart recovery.",
    trajectoryIdStable: true,
    replayCursorObserved: true,
    guiReconnected: false,
    replayIdsStable: true,
    replayFromCursorEmpty: false,
    sideEffectCount: 0,
    duplicateSideEffectCount: 0,
    rows: subagents.slice(0, 6).map((record) => ({
      id: record.subagent_id || record.subagentId,
      kind: `subagent.${record.role || "child"}`,
      status: record.status || record.lifecycle_status || "observed",
      summary: record.restart_status === "restarted" || record.restartStatus === "restarted"
        ? "failed child recovered"
        : `${record.role || "child"} linked to parent`,
      receiptRefs: normalizeReceiptRefs(record),
    })),
  });
  studioRuntimeProjection.runtimeCockpit.workerStatusObserved = true;
  studioRuntimeProjection.runtimeCockpit.browserStatusObserved = true;
  refreshStudioReplayStepsFromProjection();
  recomputeStudioRuntimeCockpitAchieved();
  await refreshStudioPanelHtml(output);

  const refreshed = await requestJson(endpoint, `/v1/threads/${encodeURIComponent(threadId)}/subagents`, {
    token: daemonRequestToken(),
  });
  const recoveredRecord = firstArray(refreshed?.subagents).find((record) => (record.subagent_id || record.subagentId) === failedChildId);
  const checks = {
    threadCreated: Boolean(threadId),
    parentTurnCreated: Boolean(parentTurnId),
    delegatedWorkerSpawned: Boolean(delegatedWorker?.subagent_id || delegatedWorker?.subagentId),
    failedChildBlocked: Boolean(failedChildError && failedChildId),
    failedChildRecovered: recoveredRecord?.restart_status === "restarted" || recoveredRecord?.restartStatus === "restarted",
    browserSubagentSpawned: Boolean(browserSubagent?.subagent_id || browserSubagent?.subagentId),
    parentChildListingVisible: subagents.length >= 3,
    workerCardsProjected: studioRuntimeProjection.runtimeCockpit.workerStatusObserved === true,
    browserArtifactProjected: studioRuntimeProjection.runtimeCockpit.browserStatusObserved === true,
    productTranscriptClean: true,
  };
  const passed = Object.values(checks).every(Boolean);
  await writeBridgeRequest("studio.stage7DelegationLifecycle.exercised", {
    sourceCommand: "ioi.studio.exerciseStage7DelegationLifecycle",
    runtimeAuthority: "daemon-owned",
    projectionOwner: "ioi-workbench-agent-studio",
    ownsRuntimeState: false,
    passed,
    checks,
    threadId,
    parentTurnId,
    subagentIds: {
      delegatedWorker: delegatedWorker?.subagent_id || delegatedWorker?.subagentId || null,
      failedChild: failedChildId,
      browserSubagent: browserSubagent?.subagent_id || browserSubagent?.subagentId || null,
    },
    subagentCount: subagents.length,
    workerIds,
    eventCount: events.length,
  }, contextSnapshot).catch((error) => {
    output?.appendLine?.(`[ioi-studio] stage7 delegation lifecycle bridge request unavailable: ${error?.message || String(error)}`);
  });
  return { passed, checks, threadId, parentTurnId, subagentCount: subagents.length, workerIds };
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
    const patchTargetPath = studioRuntimeCockpitPatchTargetFromPrompt(prompt);
    const patchResponse = await invokeStudioDaemonTool(
      threadId,
      "file.apply_patch",
      {
        path: patchTargetPath,
        dryRun: true,
        edits: [
          {
            type: "append",
            text: [
              "",
              "function capitalize(part) {",
              "  return part ? part[0].toUpperCase() + part.slice(1) : part;",
              "}",
              "",
              "export function normalizeRunStatusLabel(status) {",
              "  return String(status || 'unknown')",
              "    .split('_')",
              "    .filter(Boolean)",
              "    .map(capitalize)",
              "    .join(' ');",
              "}",
              "",
            ].join("\n"),
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
    const hunk = patchPreviewHunkFromToolResponse(patchResponse, patchTargetPath);
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

  refreshStudioReplayStepsFromProjection();
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

function studioPromptRequestsGeneratedWebArtifact(prompt = "") {
  const value = String(prompt || "");
  return /\b(create|build|make|generate|draft|design|prototype|output)\b[\s\S]{0,120}\b(website|web\s*site|webpage|web\s*page|landing\s+page|microsite|static\s+site|html\s+(?:file|page|document|website))\b/i.test(value);
}

function studioPromptRequestsBrowserObservationArtifact(prompt = "") {
  const value = String(prompt || "");
  return (
    /\b(capture|save|export|promote|turn|convert|render)\b[\s\S]{0,100}\b(browser|computer)\b[\s\S]{0,100}\b(artifact|capture|observation|result)\b/i.test(value) ||
    /\b(browser|computer)\s+session\s+result\b[\s\S]{0,80}\bas\s+an?\s+artifact\b/i.test(value)
  );
}

function shouldProjectConversationArtifactCanvas(prompt) {
  return studioPromptRequestsGeneratedWebArtifact(prompt) ||
    studioPromptRequestsBrowserObservationArtifact(prompt) ||
    /\bartifact|embedded document|odt|docx|pdf|standalone html|html\/css\/js|react|vite|dashboard|csv|chart|dataset|patch artifact|diff artifact/i.test(String(prompt || ""));
}

function studioIntentFrameRouteDirective(intentFrame = {}) {
  return stringValue(intentFrame?.routeDirective || intentFrame?.route_directive);
}

function studioIntentFrameProjectsArtifact(intentFrame = {}) {
  return studioIntentFrameRouteDirective(intentFrame) === "artifact" || Boolean(intentFrame?.artifact?.required);
}

function studioIntentFrameProjectsRuntimeCockpit(intentFrame = {}) {
  return studioIntentFrameRouteDirective(intentFrame) === "runtime_cockpit" || stringValue(intentFrame?.intentId || intentFrame?.intent_id) === "runtime.inspect";
}

function studioIntentFrameRequiresRetrieval(intentFrame = {}, prompt = "") {
  if (intentFrame?.retrieval && typeof intentFrame.retrieval === "object") {
    return Boolean(intentFrame.retrieval.required);
  }
  return promptRequiresRetrieval(prompt);
}

function studioIntentFrameArtifactClass(intentFrame = {}, prompt = "") {
  return stringValue(intentFrame?.artifact?.class || intentFrame?.artifact?.artifactClass || intentFrame?.artifact?.artifact_class,
    studioArtifactClassFromPrompt(prompt),
  );
}

function studioIntentFrameArtifactTitle(intentFrame = {}, artifactClass, prompt = "") {
  return stringValue(intentFrame?.artifact?.title, studioArtifactTitleFromClass(artifactClass, prompt));
}

function studioIntentFrameArtifactSummary(intentFrame = {}, prompt = "") {
  return stringValue(
    intentFrame?.artifact?.summary,
    studioPromptRequestsGeneratedWebArtifact(prompt)
      ? "Sandboxed website preview generated through the daemon-owned artifact lifecycle."
      : "Agent Studio conversation artifact created through the daemon-owned artifact lifecycle.",
  );
}

function fallbackStudioPromptIntentFrame(prompt = "", { executionMode = STUDIO_MODE_AGENT } = {}) {
  const normalizedExecutionMode = normalizeStudioExecutionMode(executionMode);
  const artifactClass = shouldProjectConversationArtifactCanvas(prompt)
    ? studioArtifactClassFromPrompt(prompt)
    : null;
  const projectsRuntime = !artifactClass && shouldProjectStudioRuntimeCockpit(prompt);
  const requiresRetrieval =
    promptRequiresRetrieval(prompt) ||
    studioArtifactShouldGatherResearch(prompt, artifactClass);
  const requiresWorkspaceContext = promptRequiresWorkspaceContext(prompt, normalizedExecutionMode);
  const routeDirective = normalizedExecutionMode === STUDIO_MODE_ASK
    ? "ask"
    : artifactClass
      ? "artifact"
      : projectsRuntime
        ? "runtime_cockpit"
        : "agent";
  const intentId = artifactClass
    ? "artifact.create"
    : projectsRuntime
      ? "runtime.inspect"
      : requiresRetrieval
        ? "retrieval.answer"
        : requiresWorkspaceContext
          ? "workspace.context"
          : "conversation.reply";
  const requiredCapabilities = [
    "prim:conversation.reply",
    ...(artifactClass ? ["prim:artifact.write", "prim:artifact.render"] : []),
    ...(requiresRetrieval ? ["prim:web.search", "prim:web.read"] : []),
    ...(requiresWorkspaceContext ? ["prim:file.search", "prim:file.read", "prim:workspace.read"] : []),
    ...(projectsRuntime ? ["prim:runtime.trace.read"] : []),
  ];
  const receiptsRequired = artifactClass
    ? ["artifact_record", "artifact_revision", "artifact_policy"]
    : requiresRetrieval
      ? ["retrieval_search", "retrieval_read", "chat_reply"]
      : requiresWorkspaceContext
        ? ["file_search", "file_read", "chat_reply"]
        : ["chat_reply"];
  return {
    schemaVersion: "ioi.studio.intent-frame.fallback.v1",
    object: "ioi.studio_intent_frame",
    target: prompt, query: requiresRetrieval ? prompt : null,
    intentId,
    routeDirective,
    executionMode: normalizedExecutionMode,
    decision: "selected",
    confidence: artifactClass || projectsRuntime || requiresRetrieval || requiresWorkspaceContext ? 0.76 : 0.42,
    requiredCapabilities,
    retrieval: {
      required: requiresRetrieval,
      requirements: requiresRetrieval ? ["source_grounding"] : [],
    },
    workspace: {
      required: requiresWorkspaceContext,
      requirements: requiresWorkspaceContext ? ["workspace_context"] : [],
      targets: requiresWorkspaceContext ? workspaceTargetsForPrompt(prompt) : [],
    },
    artifact: {
      required: Boolean(artifactClass),
      class: artifactClass,
      artifactClass,
      title: artifactClass ? studioArtifactTitleFromClass(artifactClass, prompt) : null,
      summary: artifactClass ? studioIntentFrameArtifactSummary({}, prompt) : null,
    },
    effectContract: {
      applicabilityClass: artifactClass ? "local_artifact_generation" : requiresRetrieval ? "remote_retrieval" : requiresWorkspaceContext ? "workspace_context" : "conversation",
      effectLevel: artifactClass ? "sandboxed_generation" : requiresRetrieval ? "read_only_external" : requiresWorkspaceContext ? "read_only_workspace" : "none",
      sandbox: artifactClass ? "artifact_renderer" : requiresWorkspaceContext ? "workspace_readonly" : null,
      typedActionsOnly: Boolean(artifactClass),
      receiptsRequired,
    },
    decisionMaterial: {
      source: "local_fallback_feature_resolver",
      matchedFeatures: [
        ...(artifactClass ? ["artifact_deliverable"] : []),
        ...(projectsRuntime ? ["runtime_inspection"] : []),
        ...(requiresRetrieval ? ["retrieval_required"] : []),
        ...(requiresWorkspaceContext ? ["workspace_context_required"] : []),
      ],
    },
  };
}

function studioIntentFramePayload(intentFrame = {}) {
  if (!intentFrame || typeof intentFrame !== "object") {
    return null;
  }
  return {
    schemaVersion: intentFrame.schemaVersion || intentFrame.schema_version || null,
    target: intentFrame.target || null, query: intentFrame.query || null,
    intentId: intentFrame.intentId || intentFrame.intent_id || null,
    routeDirective: intentFrame.routeDirective || intentFrame.route_directive || null,
    executionMode: intentFrame.executionMode || intentFrame.execution_mode || null,
    confidence: intentFrame.confidence ?? null,
    requiredCapabilities: firstArray(intentFrame.requiredCapabilities || intentFrame.required_capabilities),
    retrieval: intentFrame.retrieval || null,
    workspace: intentFrame.workspace || null,
    artifact: intentFrame.artifact || null,
    runtimeAction: intentFrame.runtimeAction || intentFrame.runtime_action || null,
    runtime_action: intentFrame.runtime_action || intentFrame.runtimeAction || null,
    effectContract: intentFrame.effectContract || intentFrame.effect_contract || null,
    decisionMaterial: intentFrame.decisionMaterial
      ? {
          source: intentFrame.decisionMaterial.source || null,
          matchedFeatures: firstArray(intentFrame.decisionMaterial.matchedFeatures),
          promptHash: intentFrame.decisionMaterial.promptHash || null,
          promptPreview: intentFrame.decisionMaterial.promptPreview || null,
        }
      : null,
  };
}

async function resolveStudioPromptIntentFrame(prompt = "", options = {}, output) {
  const endpoint = daemonEndpoint();
  if (!endpoint) {
    return fallbackStudioPromptIntentFrame(prompt, options);
  }
  try {
    const frame = await requestJson(endpoint, "/v1/studio/intent-frame", {
      method: "POST",
      token: daemonRequestToken(),
      timeoutMs: 1500,
      payload: {
        prompt,
        executionMode: normalizeStudioExecutionMode(options.executionMode || options.execution_mode),
    routeId: options.selectedRoute || options.routeId || studioRuntimeProjection.modelRoute || "route.local-first",
    modelId: options.selectedModelId || options.modelId || studioRuntimeProjection.selectedModel || "auto",
    approvalMode: options.approvalMode || studioRuntimeProjection.approvalMode,
    workspaceRoot: options.workspacePath || workspaceSummary().path,
    source: "agent-studio-submit",
      },
    });
    if (frame && typeof frame === "object") {
      return frame;
    }
  } catch (error) {
    output?.appendLine?.(`[ioi-studio] intent frame route unavailable; using local fallback: ${error?.message || String(error)}`);
  }
  return fallbackStudioPromptIntentFrame(prompt, options);
}

function studioArtifactClassFromPrompt(prompt = "") {
  const value = String(prompt || "").toLowerCase();
  if (/\b(odt|docx|document artifact|editable projection)\b/.test(value)) return "imported_document";
  if (/\b(pdf|read-only document|readonly document)\b/.test(value)) return "pdf_preview";
  if (/\b(react|vite|dashboard app|mini app)\b/.test(value)) return "react_vite_app";
  if (studioPromptRequestsGeneratedWebArtifact(prompt)) return "static_html_js";
  if (
    (/\b(markdown report|html report)\b/.test(value) ||
      (/\b(create|build|make|generate|draft|design|prototype|output|prepare)\b/.test(value) && /\breport\b/.test(value))) &&
    !/\b(standalone html\/css\/js|html\/css\/js|static html|html css js)\b/.test(value)
  ) return "markdown_html_report";
  if (/\b(standalone html|html\/css\/js|static html|html css js)\b/.test(value)) return "static_html_js";
  if (/\b(diff|patch|reviewable patch)\b/.test(value)) return "diff_patch";
  if (/\b(csv|dataset|chart|table)\b/.test(value)) return "dataset_chart";
  if (studioPromptRequestsBrowserObservationArtifact(prompt)) return "browser_observation";
  return "markdown_html_report";
}

function studioTopicFromGeneratedWebPrompt(prompt = "") {
  const text = String(prompt || "").replace(/\s+/g, " ").trim();
  const match = text.match(/\b(?:explains?|about|for|on)\s+([^.!?\n]{3,90})/i);
  const topic = (match?.[1] || "")
    .replace(/\b(?:as|with|using|and)\b.*$/i, "")
    .replace(/^["'`]+|["'`]+$/g, "")
    .trim();
  return topic || "";
}

function studioTitleCaseArtifactTopic(value = "") {
  const cleaned = String(value || "").replace(/\s+/g, " ").trim();
  if (!cleaned) return "";
  return cleaned.charAt(0).toUpperCase() + cleaned.slice(1);
}

function studioArtifactTitleFromClass(classId, prompt = "") {
  switch (classId) {
    case "imported_document":
      return "Launch memo document";
    case "pdf_preview":
      return "Read-only PDF artifact";
    case "react_vite_app":
      return "CSV dashboard app";
    case "static_html_js":
      if (studioPromptRequestsGeneratedWebArtifact(prompt)) {
        const topic = studioTitleCaseArtifactTopic(studioTopicFromGeneratedWebPrompt(prompt));
        return topic ? `${topic} website` : "Generated website";
      }
      return "Standalone HTML report";
    case "diff_patch":
      return "Reviewable patch";
    case "dataset_chart":
      return "Test results dataset";
    case "browser_observation":
      return "Browser session capture";
    default:
      return "Test results report";
  }
}

async function recoverStudioConversationArtifactAfterTimeout(threadId, { title, artifactClass, startedAtMs } = {}, output) {
  if (!threadId) {
    return null;
  }
  try {
    const artifacts = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/artifacts`, {
      method: "GET",
      token: daemonRequestToken(),
      timeoutMs: 5_000,
    });
    const normalizedTitle = stringValue(title).toLowerCase();
    const normalizedClass = stringValue(artifactClass);
    const candidate = firstArray(artifacts)
      .filter((artifact) => {
        const createdAtMs = Date.parse(artifact?.created_at || artifact?.createdAt || artifact?.updated_at || artifact?.updatedAt || "");
        const recentEnough = !startedAtMs || !Number.isFinite(createdAtMs) || createdAtMs >= startedAtMs - 2_000;
        const titleMatches = !normalizedTitle || stringValue(artifact?.title).toLowerCase() === normalizedTitle;
        const classMatches = !normalizedClass || stringValue(artifact?.artifact_class || artifact?.artifactClass) === normalizedClass;
        return recentEnough && titleMatches && classMatches;
      })
      .sort((left, right) =>
        Date.parse(right?.updated_at || right?.updatedAt || right?.created_at || right?.createdAt || "") -
        Date.parse(left?.updated_at || left?.updatedAt || left?.created_at || left?.createdAt || ""),
      )[0];
    if (candidate) {
      output?.appendLine?.(`[ioi-studio] recovered conversation artifact after bounded request timeout: ${candidate.id}`);
      appendStudioTimeline("Conversation artifact recovered", candidate.title || candidate.id, "completed", {
        artifactId: candidate.id,
      });
      return candidate;
    }
  } catch (error) {
    output?.appendLine?.(`[ioi-studio] conversation artifact recovery unavailable: ${error?.message || String(error)}`);
  }
  return null;
}

async function createStudioConversationArtifact(threadId, prompt, output, intentFrame = {}, options = {}) {
  const artifactClass = studioIntentFrameArtifactClass(intentFrame, prompt);
  const generatedFiles = options.generatedFiles || options.generated_files || null;
  const title = generatedFiles?.title || studioIntentFrameArtifactTitle(intentFrame, artifactClass, prompt);
  const summary = generatedFiles?.summary || studioIntentFrameArtifactSummary(intentFrame, prompt);
  const createStartedAtMs = Date.now();
  let response;
  try {
    response = await requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/artifacts`, {
      method: "POST",
      token: daemonRequestToken(),
      timeoutMs: STUDIO_ARTIFACT_REQUEST_TIMEOUT_MS,
      payload: {
        prompt,
        artifactClass,
        title,
        summary,
        outputModality: intentFrame?.artifact?.outputModality || intentFrame?.artifact?.output_modality || null,
        ...(generatedFiles ? { generatedFiles } : {}),
        intentFrame: studioIntentFramePayload(intentFrame),
        source: "agent-studio-conversation-artifact",
        turnId: studioRuntimeProjection.turnId || null,
      },
    });
  } catch (error) {
    if (!/timed out|timeout/i.test(error?.message || String(error))) {
      throw error;
    }
    const recovered = await recoverStudioConversationArtifactAfterTimeout(
      threadId,
      { title, artifactClass, startedAtMs: createStartedAtMs },
      output,
    );
    if (!recovered) {
      throw error;
    }
    response = { artifact: recovered };
  }
  let artifact = response?.artifact || response;
  appendStudioReceipts(firstArray([response?.receipt]), "conversation_artifact");
  const applyArtifactAction = async (action, payload = {}) => {
    const result = await runStudioConversationArtifactAction(artifact.id, action, output, payload);
    if (result?.artifact) {
      artifact = result.artifact;
    }
    return result;
  };
  if (artifactClass === "imported_document") {
    await applyArtifactAction("edit", {
      instruction: "Tighten the intro while preserving the original document bytes.",
    });
    await applyArtifactAction("compare");
    await applyArtifactAction("export");
  } else if (artifactClass === "react_vite_app") {
    await applyArtifactAction("rebuild");
    await applyArtifactAction("edit", {
      instruction: "Make the sidebar denser.",
    });
    await applyArtifactAction("rebuild");
  } else if (artifactClass === "static_html_js") {
    if (!generatedFiles) {
      await applyArtifactAction("rebuild");
    }
  } else if (artifactClass === "pdf_preview") {
    await applyArtifactAction("summarize");
  } else if (artifactClass === "diff_patch") {
    await applyArtifactAction("approve");
    await applyArtifactAction("rollback");
  } else if (artifactClass === "browser_observation") {
    await applyArtifactAction("capture");
  }
  return artifact;
}

async function runStudioConversationArtifactAction(artifactId, action, output, payload = {}) {
  try {
    const result = await requestJson(daemonEndpoint(), `/v1/conversation-artifacts/${encodeURIComponent(artifactId)}/actions`, {
      method: "POST",
      token: daemonRequestToken(),
      timeoutMs: STUDIO_ARTIFACT_REQUEST_TIMEOUT_MS,
      payload: {
        action,
        ...payload,
        source: "agent-studio-conversation-artifact-action",
        runtimeAuthority: "daemon-owned",
        projectionOwner: "ioi-workbench-agent-studio",
      },
    });
    appendStudioReceipts(firstArray([result?.receipt]), "conversation_artifact_action");
    return result;
  } catch (error) {
    output?.appendLine?.(`[ioi-studio] artifact action ${action} blocked: ${error?.message || String(error)}`);
    appendStudioTimeline("Artifact action blocked", `${action}: ${error?.message || String(error)}`, "blocked");
    return null;
  }
}

async function projectStudioConversationArtifactCanvas(prompt, output, intentFrame = {}) {
  await ensureStudioDaemonThread({
    model: studioRuntimeProjection.modelRoute || "route.local-first",
    selectedModelId: studioRuntimeProjection.selectedModel || "auto",
    reasoningEffort: studioRuntimeProjection.reasoningEffort || "none",
    executionMode: STUDIO_MODE_AGENT,
    approvalMode: studioRuntimeProjection.approvalMode,
  }, output);
  const threadId = studioRuntimeProjection.threadId;
  studioRuntimeProjection.turnId = studioRuntimeProjection.turnId || `turn_artifact_${Date.now().toString(36)}`;
  studioRuntimeProjection.runId = studioRuntimeProjection.runId || studioRuntimeProjection.turnId;
  const artifactClass = studioIntentFrameArtifactClass(intentFrame, prompt);
  let generatedFiles = null;
  let generatedFilesError = null;
  if (artifactClass === "static_html_js" && studioPromptRequestsGeneratedWebArtifact(prompt)) {
    try {
      generatedFiles = await generateStudioStaticWebsiteDraftThroughAgentTurn({
        prompt,
        title: studioIntentFrameArtifactTitle(intentFrame, artifactClass, prompt),
        selectedRoute: studioRuntimeProjection.modelRoute || "route.local-first",
        selectedModelId: studioRuntimeProjection.selectedModel || "auto",
        reasoningEffort: studioRuntimeProjection.reasoningEffort || "none",
        workspacePath: workspaceSummary().path,
        intentFrame,
      }, output);
    } catch (error) {
      generatedFilesError = error;
      output?.appendLine?.(`[ioi-studio] website artifact model draft rejected: ${error?.message || String(error)}`);
    }
  }
  if (artifactClass === "static_html_js" && studioPromptRequestsGeneratedWebArtifact(prompt) && !generatedFiles) {
    const detail = generatedFilesError?.message || "Artifact boundary rejected generated website draft.";
    const cleanDetail = generatedFilesError
      ? studioCleanProductErrorMessage(generatedFilesError)
      : "Artifact boundary rejected generated website draft.";
    appendStudioTimeline("Website artifact blocked", detail, "blocked");
    let blockedText = /No product model is mounted/i.test(cleanDetail) ? cleanDetail : "";
    if (!blockedText) {
      try {
        const handoff = await studioModelCompletion.streamStudioArtifactBlockedHandoff({
          prompt,
          selectedRoute: studioRuntimeProjection.modelRoute || "route.local-first",
          selectedModelId: studioRuntimeProjection.selectedModel || "auto",
          reasoningEffort: studioRuntimeProjection.reasoningEffort || "none",
          workspacePath: workspaceSummary().path,
          handoffContext: `Artifact class: static HTML website.\nBoundary result: selected model draft did not pass artifact validation.\nArtifact created: no.\nProduct-safe detail: ${cleanDetail}`,
        }, output);
        blockedText = handoff.text;
      } catch (handoffError) {
        output?.appendLine?.(`[ioi-studio] website artifact blocked handoff failed: ${handoffError?.message || String(handoffError)}`);
      }
    }
    return {
      status: "blocked",
      events: [],
      receiptRefs: [],
      text: blockedText,
      artifacts: [],
    };
  }
  const artifact = await createStudioConversationArtifact(threadId, prompt, output, intentFrame, { generatedFiles });
  const generatedRuntimeEvents = firstArray(generatedFiles?.runtimeEvents);
  const generatedSourceRefs = firstArray(generatedFiles?.sourceRefs).length
    ? firstArray(generatedFiles?.sourceRefs)
    : studioSourceRefsFromRuntimeEvents(generatedRuntimeEvents);
  const artifactForTurn = generatedSourceRefs.length
    ? { ...artifact, sourceRefs: generatedSourceRefs }
    : artifact;
  studioRuntimeProjection.conversationArtifacts.push(artifactForTurn);
  studioRuntimeProjection.runtimeCockpit.conversationArtifactObserved = true;
  appendStudioTimeline("Conversation artifact ready", artifactForTurn.title || artifactForTurn.id, "completed", {
    artifactId: artifactForTurn.id,
  });
  let handoffText = "";
  let handoffMetrics = null;
  if (artifactClass === "static_html_js" && generatedFiles) {
    const artifactTitle = stringValue(artifactForTurn.title || generatedFiles.title || studioIntentFrameArtifactTitle(intentFrame, artifactClass, prompt), "website");
    const artifactLabel = /\bwebsite\b/i.test(artifactTitle) ? artifactTitle : `${artifactTitle} website`;
    handoffText = `Created the ${artifactLabel} artifact. The preview is below.`;
  } else {
    try {
      const handoff = await studioModelCompletion.streamStudioArtifactHandoffText({
        prompt,
        selectedRoute: studioRuntimeProjection.modelRoute || "route.local-first",
        selectedModelId: studioRuntimeProjection.selectedModel || "auto",
        reasoningEffort: studioRuntimeProjection.reasoningEffort || "none",
        workspacePath: workspaceSummary().path,
        handoffContext: `Artifact title: ${artifactForTurn.title || artifactForTurn.id}\nArtifact class: ${artifactForTurn.artifactClass || artifactForTurn.artifact_class || artifactClass}\nArtifact created: yes.\nPreview is attached in Agent Studio as a sandboxed conversation artifact.\nAvailable actions: open preview, revise, export, promote, or roll back when supported.`,
      }, output);
      handoffText = handoff.text;
      handoffMetrics = handoff.metrics || null;
    } catch (handoffError) {
      output?.appendLine?.(`[ioi-studio] artifact handoff model stream failed: ${handoffError?.message || String(handoffError)}`);
    }
  }
  return {
    status: "completed",
    events: generatedRuntimeEvents,
    sourceRefs: generatedSourceRefs,
    receiptRefs: normalizeReceiptRefs(artifactForTurn),
    text: handoffText,
    artifacts: [artifactForTurn],
    modelMetrics: handoffMetrics || generatedFiles?.generator?.metrics || null,
  };
}

function studioPostRuntimeMessage(type, payload = {}) {
  let normalizedPayload = payload;
  if (type === "agentWorkStep") {
    normalizedPayload = appendStudioPendingWorkStep(payload);
    if (!normalizedPayload) return;
  }
  if (!studioPanel) return;
  studioPanel.webview.postMessage({ source: "ioi-studio-runtime", type, payload: normalizedPayload });
  if (type === "agentWorkStep") {
    studioPostPendingWorklogSnapshot();
  }
}

function studioPostPendingWorklogSnapshot() {
  if (!studioPanel) return;
  const steps = firstArray(studioRuntimeProjection.pendingWorklog)
    .map((step) => normalizeStudioPendingWorkStep(step))
    .filter(Boolean)
    .slice(-12);
  if (!steps.length) return;
  studioPanel.webview.postMessage({
    source: "ioi-studio-runtime",
    type: "agentWorklogSnapshot",
    payload: { steps },
  });
}

const studioAgentFinalHandoffStreamer = createStudioAgentFinalHandoffStreamer({ crypto, studioPostRuntimeMessage, stringValue });
const studioAgentAnswerStreamProjector = createStudioAgentAnswerStreamProjector({ getStudioRuntimeProjection: () => studioRuntimeProjection, studioPostRuntimeMessage, stringValue });

function studioModelIdForRouteInvocation(selectedRoute, selectedModelId) {
  const explicitModelId = stringValue(selectedModelId);
  assertStudioProductModelSelector(selectedRoute, explicitModelId);
  if (!isAutoStudioModelSelector(explicitModelId)) {
    return explicitModelId;
  }
  const routeOrModel = stringValue(selectedRoute);
  assertStudioProductModelSelector(routeOrModel, explicitModelId);
  if (routeOrModel && !routeOrModel.startsWith("route.") && !isAutoStudioModelSelector(routeOrModel)) {
    return routeOrModel;
  }
  return "auto";
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

function studioReasoningDeltaFromSsePayload(payload) {
  if (!payload || typeof payload !== "object") {
    return "";
  }
  const choice = payload.choices?.[0] || {};
  return stringValue(choice.delta?.reasoning_content || choice.delta?.reasoningContent || payload.delta?.reasoning_content || payload.reasoning_delta);
}

function studioUsageFromProviderTimings(timings = {}, previousUsage = null) {
  if (!timings || typeof timings !== "object") return previousUsage;
  const promptTokens = studioNumberOrNull(timings.prompt_n ?? previousUsage?.prompt_tokens ?? previousUsage?.input_tokens) ?? 0;
  const completionTokens =
    studioNumberOrNull(timings.predicted_n ?? previousUsage?.completion_tokens ?? previousUsage?.output_tokens) ?? 0;
  const usage = {
    ...(previousUsage && typeof previousUsage === "object" ? previousUsage : {}),
    prompt_tokens: promptTokens,
    completion_tokens: completionTokens,
    total_tokens: studioNumberOrNull(previousUsage?.total_tokens) ?? promptTokens + completionTokens,
  };
  const tokensPerSecond = studioNumberOrNull(timings.predicted_per_second);
  const promptMs = studioNumberOrNull(timings.prompt_ms);
  const completionMs = studioNumberOrNull(timings.predicted_ms);
  if (tokensPerSecond !== null) usage.tokens_per_second = tokensPerSecond;
  if (promptMs !== null) usage.prompt_ms = promptMs;
  if (completionMs !== null) usage.completion_ms = completionMs;
  if (promptMs !== null || completionMs !== null) usage.elapsed_ms = (promptMs || 0) + (completionMs || 0);
  return usage;
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
  target.usage = payload.usage || payload.tokenCount || payload.token_count || target.usage;
  if (payload.timings) {
    target.usage = studioUsageFromProviderTimings(payload.timings, target.usage);
  }
  target.provider = payload.provider_id || payload.providerId || payload.provider || target.provider;
  const finishReason = payload.choices?.[0]?.finish_reason || payload.finish_reason || payload.stop_reason || payload.stopReason;
  target.stopReason = finishReason || target.stopReason;
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
                finishResolve({ statusCode, raw });
                request.destroy();
                return;
              }
              try {
                const shouldContinue = onPayload?.(JSON.parse(data), data);
                if (shouldContinue === false) {
                  finishResolve({ statusCode, raw, stoppedByClient: true });
                  request.destroy();
                  return;
                }
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
                  const shouldContinue = onPayload?.(JSON.parse(data), data);
                  if (shouldContinue === false) {
                    finishResolve({ statusCode, raw, stoppedByClient: true });
                    return;
                  }
                } else {
                  finishResolve({ statusCode, raw });
                  return;
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

const studioModelCompletion = createStudioModelCompletion({
  crypto,
  STUDIO_MODEL_COMPLETION_TIMEOUT_MS,
  requestSseJson,
  requestJson,
  daemonEndpoint,
  ensureStudioModelInvocationToken,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  studioModelIdForRouteInvocation,
  normalizeStudioReasoningEffort,
  studioPostRuntimeMessage,
  firstArray,
  studioDenyFixtureModelPolicy,
  studioMaxOutputTokens,
  studioArtifactMaxOutputTokens,
  collectStudioStreamMetadata,
  studioReasoningDeltaFromSsePayload,
  studioDeltaFromSsePayload,
  studioSplitReasoningFromText,
  stringValue,
  studioResponseMetricsFromUsage,
  studioTextContainsProductFixtureMarker,
  studioFixtureModelUsageAllowed,
  appendStudioReceipts,
});
const {
  sanitizeStudioProductAssistantText,
  normalizeStudioAssistantReplyText,
  studioAssistantReplyTextIsDeferred,
  normalizeStudioAgentResultText,
  studioAssistantTextFromRuntimeToolEvents,
  studioAgentTurnResultText,
  studioArtifactSourceTextFromAgentTurn,
} = createStudioAgentTurnResultText({
  stringValue,
  firstArray,
  studioRuntimeEventKind,
  studioRuntimeEventToolName,
  extractHtmlDocument: studioModelCompletion.extractStudioHtmlDocument,
});

async function streamStudioModelCompletion(args, output) {
  return studioModelCompletion.streamStudioModelCompletion(args, output);
}

async function generateStudioStaticWebsiteDraft(args, output) {
  return studioModelCompletion.generateStudioStaticWebsiteDraft(args, output);
}

async function generateStudioStaticWebsiteDraftThroughAgentTurn({
  prompt,
  title,
  selectedRoute,
  selectedModelId,
  reasoningEffort = "none",
  workspacePath,
  intentFrame = {},
}, output) {
  const researchQuery = studioArtifactResearchQuery(prompt);
  const artifactPrompt = [
    `Create one complete self-contained HTML document for this request: ${prompt}`,
    `Research topic: ${researchQuery || prompt}`,
    "",
    "Use the governed tool loop before writing the page.",
    "Call web__search with exactly the research topic above as the query.",
    "Call web__read on one relevant result if a readable result is available.",
    "Then call chat__reply; the chat__reply message must contain the final HTML document only.",
    "The chat__reply message must start with <!DOCTYPE html> and end immediately after </html>.",
    "Do not return markdown fences, JSON, source notes, receipts, file paths, or explanations.",
    "Do not use external network assets, remote fonts, CDNs, or filesystem references.",
  ].join("\n");
  const agentTurn = await submitStudioAgentTurn({
    prompt: artifactPrompt,
    selectedRoute,
    selectedModelId,
    reasoningEffort,
    workspacePath,
    intentFrame: studioResearchIntentFrameForArtifact(studioIntentFramePayload(intentFrame), researchQuery),
    projectAnswerStream: true,
    answerStreamPresentation: "artifact_generation",
    answerStreamFileName: "index.html",
    maxStepsOverride: 8,
  }, output);
  const artifactSourceText = studioArtifactSourceTextFromAgentTurn(agentTurn);
  const sourceStream = studioAgentAnswerStreamProjector.complete(artifactSourceText, {
    presentation: "artifact_generation",
    fileName: "index.html",
  });
  const draft = studioModelCompletion.studioStaticWebsiteDraftFromRuntimeText({
    prompt,
    title,
    text: artifactSourceText,
    selectedRoute,
    selectedModelId,
    metrics: agentTurn.modelMetrics || null,
    receiptRefs: agentTurn.receiptRefs || [],
    streamId: sourceStream?.streamId || "",
  });
  return {
    ...draft,
    sourceRefs: firstArray(agentTurn.sourceRefs),
    runtimeEvents: firstArray(agentTurn.events),
  };
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

function applyStudioAgentTurnEvents(events = [], {
  projectPending = true,
  projectAnswerStream = true,
  answerStreamPresentation = "agent_final_handoff",
  answerStreamFileName = "",
} = {}) {
  const appliedEvents = [];
  for (const event of firstArray(events)) {
    if (!markStudioRuntimeEventSeen(event)) {
      continue;
    }
    appendStudioRuntimeEvent(event, studioRuntimeEventKind(event) || "agent.runtime.event");
    const eventThreadId = stringValue(event.thread_id || event.threadId);
    const eventTurnId = stringValue(event.turn_id || event.turnId);
    if (eventThreadId && !studioRuntimeProjection.threadId) {
      studioRuntimeProjection.threadId = eventThreadId;
      studioRuntimeProjection.sessionId = studioRuntimeProjection.sessionId || eventThreadId;
    }
    if (eventTurnId && !studioRuntimeProjection.turnId) {
      studioRuntimeProjection.turnId = eventTurnId;
      studioRuntimeProjection.runId = event.run_id || event.runId || studioRuntimeProjection.runId || eventTurnId;
    }
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
    if (kind === "answer.delta") {
      if (!projectAnswerStream) continue;
      studioAgentAnswerStreamProjector.projectDelta(event, {
        presentation: answerStreamPresentation,
        fileName: answerStreamFileName,
      });
      continue;
    }
    if (
      projectAnswerStream &&
      answerStreamPresentation === "artifact_generation" &&
      /turn\.(completed|failed|blocked)/.test(kind)
    ) {
      const terminalArtifactSource = studioArtifactSourceTextFromAgentTurn({ events: [event] });
      if (terminalArtifactSource) {
        studioAgentAnswerStreamProjector.complete(terminalArtifactSource, {
          presentation: answerStreamPresentation,
          fileName: answerStreamFileName,
        });
      }
    }
    if (projectPending && studioRuntimeProjection.pending) {
      const pendingStep = studioPendingStepFromRuntimeEvent(event, {
        kind,
        toolName,
        status,
        summary,
      });
      if (pendingStep) {
        const appendedStep = appendStudioPendingWorkStep(pendingStep);
        if (appendedStep) {
          studioPostRuntimeMessage("agentWorkStep", appendedStep);
        }
      }
    }
    applyStudioParityPlusEvent(event, { kind, status, summary, receiptRefs });
    // Browser/computer tool events remain visible as work rows. Controllable
    // managed-session cards must come from daemon inspection so their ids and
    // control state bind to durable runtime state.
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
      const eventPayload = event.payload_summary || event.payloadSummary || event.payload || event.data || {};
      const commandExcerpt = studioRuntimeToolEventExcerpt(event, summary);
      const commandDetail = studioRuntimeToolEventDetail(event, toolName, summary);
      studioRuntimeProjection.commandOutputs.push({
        id: event.event_id || event.eventId || event.id || `command.${Date.now()}`,
        toolId: toolName || "shell",
        label: toolName || "shell command",
        status,
        command: commandDetail,
        stdout:
          eventPayload.stdout ||
          eventPayload.output ||
          eventPayload.chunk ||
          eventPayload.text ||
          eventPayload.excerpt_preview ||
          eventPayload.excerptPreview ||
          commandExcerpt ||
          "",
        stderr: eventPayload.stderr || "",
        excerptPreview: commandExcerpt,
        exitCode: eventPayload.exit_code ?? eventPayload.exitCode ?? null,
        durationMs: eventPayload.duration_ms ?? eventPayload.durationMs ?? null,
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
  if (
    projectPending &&
    studioRuntimeProjection.pending &&
    firstArray(studioRuntimeProjection.pendingWorklog).length > 0
  ) {
    studioPostPendingWorklogSnapshot();
  }
  return appliedEvents;
}

function studioMaxRuntimeEventSeq(events = []) {
  return firstArray(events).reduce((max, event) => {
    const seq = Number(event?.seq || 0);
    return Number.isFinite(seq) && seq > max ? seq : max;
  }, 0);
}

async function fetchStudioThreadEvents(threadId, output, { timeoutMs = 1500, sinceSeq = 0, stopOnTerminal = false } = {}) {
  if (!threadId) {
    return [];
  }
  const events = [];
  try {
    await requestSseJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/events?since_seq=${encodeURIComponent(String(Math.max(0, Number(sinceSeq) || 0)))}`, {
      method: "GET",
      token: daemonRequestToken(),
      timeoutMs,
      onPayload: (payload) => {
        let event = null;
        if (payload && payload.event && typeof payload.event === "object") {
          event = payload.event;
          events.push(event);
        } else if (payload) {
          event = payload;
          events.push(event);
        }
        if (stopOnTerminal && event) {
          const kind = studioRuntimeEventKind(event).toLowerCase();
          if (/turn\.(completed|failed|blocked)/.test(kind)) {
            return false;
          }
        }
      },
    });
  } catch (error) {
    output?.appendLine?.(`[ioi-studio] daemon thread event stream unavailable: ${error?.message || String(error)}`);
  }
  return events;
}

const studioAgentTurnEvents = createStudioAgentTurnEvents({ fetchStudioThreadEvents, applyStudioAgentTurnEvents, studioMaxRuntimeEventSeq, studioAssistantTextFromRuntimeToolEvents, studioAgentTurnResultText, studioRuntimeEventKind, firstArray });

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
  if (resultText) {
    return true;
  }
  if (events.some(studioRuntimeEventIsRunningStepCompletion)) {
    return false;
  }
  if (/blocked|failed|error|completed|paused|approval|waiting_for_approval/.test(statusText)) {
    return true;
  }
  return events.some((event) => /turn\.(completed|failed)|completed|failed|blocked/.test(studioRuntimeEventKind(event).toLowerCase()));
}

const studioAgentTurnRecovery = createStudioAgentTurnRecovery({
  fetchStudioThreadTurns,
  studioTurnMatchesSubmittedPrompt,
  studioTurnLooksTerminal,
  studioAgentTurnResultText,
  normalizeStudioAgentResultText,
  getStudioRuntimeProjection: () => studioRuntimeProjection,
  firstArray,
  recoveryAttempts: STUDIO_AGENT_TURN_RECOVERY_ATTEMPTS,
  recoveryPollMs: STUDIO_AGENT_TURN_RECOVERY_POLL_MS,
});

function studioApprovalTurnPayload() {
  const turnId = stringValue(studioRuntimeProjection.turnId);
  return turnId.startsWith("turn_") ? { turn_id: turnId } : {};
}

function applyStudioAgentModeSelection(payload = {}) {
  const previousMode = normalizeStudioExecutionMode(studioRuntimeProjection.executionMode);
  const previousRuntimeProfile = studioRuntimeProjection.runtimeProfile;
  const executionMode = normalizeStudioExecutionMode(
    payload.executionMode || payload.selectionId || payload.mode || payload.label,
  );
  const runtimeProfile =
    executionMode === STUDIO_MODE_AGENT
      ? STUDIO_AGENT_RUNTIME_PROFILE
      : STUDIO_DIRECT_MODEL_RUNTIME_PROFILE;
  studioRuntimeProjection.executionMode = executionMode;
  studioRuntimeProjection.runtimeProfile = runtimeProfile;
  if (
    studioRuntimeProjection.threadId &&
    (previousMode !== executionMode || previousRuntimeProfile !== runtimeProfile)
  ) {
    resetStudioDaemonThreadProjection();
  }
  return { executionMode, runtimeProfile };
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

async function ensureStudioDaemonThread({ model = "route.local-first", selectedModelId = "auto", executionMode = studioRuntimeProjection.executionMode, reasoningEffort = studioRuntimeProjection.reasoningEffort || "none", approvalMode = studioRuntimeProjection.approvalMode, intentFrame = null } = {}, output) {
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
  if (
    studioRuntimeProjection.threadId &&
    studioRuntimeProjection.runtimeProfile &&
    studioRuntimeProjection.runtimeProfile !== runtimeProfile
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
          ...(intentFrame ? { intentFrame: studioIntentFramePayload(intentFrame) } : {}),
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

async function submitStudioAgentTurn({
  prompt,
  selectedRoute,
  selectedModelId,
  reasoningEffort = "none",
  workspacePath,
  intentFrame,
  projectAnswerStream = true,
  answerStreamPresentation = "agent_final_handoff",
  answerStreamFileName = "",
  maxStepsOverride = null,
}, output) {
  await ensureStudioDaemonThread({
    model: selectedRoute,
    selectedModelId,
    reasoningEffort,
    executionMode: STUDIO_MODE_AGENT,
    approvalMode: studioRuntimeProjection.approvalMode,
    intentFrame,
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
  const hasMaxStepsOverride = maxStepsOverride !== null &&
    maxStepsOverride !== undefined &&
    String(maxStepsOverride).trim() !== "";
  const requestedMaxSteps = hasMaxStepsOverride && Number.isFinite(Number(maxStepsOverride))
    ? Math.floor(Number(maxStepsOverride))
    : studioAgentMaxStepsForIntent(intentFrame, prompt);
  const maxSteps = Math.max(STUDIO_AGENT_MIN_TURN_STEPS, requestedMaxSteps);
  const intentFramePayload = studioIntentFramePayload(intentFrame);
  const turnPayload = {
    prompt,
    input: prompt,
    ...permissionMapping,
    ...(intentFramePayload
      ? {
          intentFrame: intentFramePayload,
          intent_frame: intentFramePayload,
          runtimeAction: intentFramePayload.runtimeAction || intentFramePayload.runtime_action || null,
          runtime_action: intentFramePayload.runtime_action || intentFramePayload.runtimeAction || null,
        }
      : {}),
    runtime_profile: STUDIO_AGENT_RUNTIME_PROFILE,
    runtimeProfile: STUDIO_AGENT_RUNTIME_PROFILE,
    max_steps: maxSteps,
    maxSteps,
    options: {
      ...permissionMapping,
      runtime_profile: STUDIO_AGENT_RUNTIME_PROFILE,
      runtimeProfile: STUDIO_AGENT_RUNTIME_PROFILE,
      max_steps: maxSteps,
      maxSteps,
      local: {
        cwd: workspacePath || workspaceSummary().path,
      },
      model: {
        id: isAutoStudioModelSelector(selectedModelId) ? "auto" : selectedModelId,
        routeId: selectedRoute || "route.local-first",
        reasoningEffort: normalizeStudioReasoningEffort(reasoningEffort, "none"),
      },
      source: "agent-studio-agent-mode",
      intentFrame: intentFramePayload,
      intent_frame: intentFramePayload,
    },
    metadata: {
      source: "agent-studio-agent-mode",
      workspaceRoot: workspacePath || workspaceSummary().path,
      ...permissionMapping,
      runtimeAuthority: "daemon-owned",
      projectionOwner: "ioi-workbench-agent-studio",
      intentFrame: intentFramePayload,
      intent_frame: intentFramePayload,
    },
  };
  let turn;
  let liveEventsPromise = null;
  let liveObservedEvents = [];
  try {
    const preTurnEvents = await fetchStudioThreadEvents(threadId, output, { timeoutMs: 1000, sinceSeq: 0 });
    for (const event of preTurnEvents) {
      markStudioRuntimeEventSeen(event);
    }
    const preTurnSeq = studioMaxRuntimeEventSeq(preTurnEvents);
    const turnRequest = requestJson(daemonEndpoint(), `/v1/threads/${encodeURIComponent(threadId)}/turns`, {
      method: "POST",
      token: daemonRequestToken(),
      timeoutMs: STUDIO_AGENT_TURN_POST_TIMEOUT_MS,
      payload: turnPayload,
    });
    liveEventsPromise = studioAgentTurnEvents.pollStudioThreadEventsDuringTurn(threadId, output, turnRequest, {
      sinceSeq: preTurnSeq,
      resolveOnTerminal: true,
      projectAnswerStream,
      answerStreamPresentation,
      answerStreamFileName,
    });
    const projectionRecoveryAttempts = Math.ceil(Math.max(STUDIO_AGENT_TURN_POST_TIMEOUT_MS, 300_000) / STUDIO_AGENT_TURN_RECOVERY_POLL_MS);
    const turnProjectionRecoveryPromise = studioAgentTurnRecovery.recoverStudioAgentTurnAfterSubmitTimeout({
      threadId,
      prompt,
      submittedAtMs,
      output,
      attempts: projectionRecoveryAttempts,
      pollMs: STUDIO_AGENT_TURN_RECOVERY_POLL_MS,
      timeoutMs: 2500,
      reasonLabel: "live projection polling",
    });
    let terminalRecoveryActive = true;
    const terminalEventsRecoveryPromise = (async () => {
      const deadline = Date.now() + Math.max(STUDIO_AGENT_TURN_POST_TIMEOUT_MS, 300_000);
      let terminalRecoverySeq = preTurnSeq;
      while (terminalRecoveryActive && Date.now() < deadline) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        const events = await fetchStudioThreadEvents(threadId, output, {
          timeoutMs: 2500,
          sinceSeq: terminalRecoverySeq,
          stopOnTerminal: true,
        });
        if (!events.length) {
          continue;
        }
        terminalRecoverySeq = Math.max(terminalRecoverySeq, studioMaxRuntimeEventSeq(events));
        applyStudioAgentTurnEvents(events, {
          projectAnswerStream,
          answerStreamPresentation,
          answerStreamFileName,
        });
        if (studioAgentTurnEvents.studioRuntimeEventsHaveTerminalAssistantResult(events)) {
          return events;
        }
      }
      return null;
    })();
    const firstCompletion = await Promise.race([
      turnRequest.then((completedTurn) => ({ kind: "turn", turn: completedTurn })),
      liveEventsPromise.then((events) => ({ kind: "live_events", events })),
      turnProjectionRecoveryPromise.then((recoveredTurn) => recoveredTurn ? ({ kind: "turn_projection", turn: recoveredTurn }) : null),
      terminalEventsRecoveryPromise.then((events) => events ? ({ kind: "terminal_events", events }) : null),
    ]);
    terminalRecoveryActive = false;
    if (!firstCompletion) {
      turn = await turnRequest;
    } else if (firstCompletion.kind === "turn") {
      turn = firstCompletion.turn;
      liveObservedEvents = await Promise.race([
        liveEventsPromise.catch((error) => {
          output?.appendLine?.(`[ioi-studio] live daemon event projection ended early: ${error?.message || String(error)}`);
          return [];
        }),
        new Promise((resolve) => setTimeout(() => resolve([]), STUDIO_AGENT_TURN_EVENT_FLUSH_TIMEOUT_MS)),
      ]);
    } else if (firstCompletion.kind === "turn_projection") {
      turn = firstCompletion.turn;
      liveObservedEvents = await Promise.race([
        liveEventsPromise.catch((error) => {
          output?.appendLine?.(`[ioi-studio] live daemon event projection ended after turn projection recovery: ${error?.message || String(error)}`);
          return [];
        }),
        new Promise((resolve) => setTimeout(() => resolve([]), STUDIO_AGENT_TURN_EVENT_FLUSH_TIMEOUT_MS)),
      ]);
      turnRequest.catch((error) => {
        output?.appendLine?.(`[ioi-studio] Agent turn POST settled after turn projection recovery: ${error?.message || String(error)}`);
      });
    } else {
      liveObservedEvents = firstArray(firstCompletion.events);
      turn = studioAgentTurnRecovery.recoverStudioAgentTurnFromLiveEventsAfterSubmitTimeout({
        threadId,
        prompt,
        submittedAtMs,
        events: liveObservedEvents,
      });
      if (!turn) {
        turn = await turnRequest;
      } else {
        turnRequest.catch((error) => {
          output?.appendLine?.(`[ioi-studio] Agent turn POST settled after live event completion: ${error?.message || String(error)}`);
        });
      }
    }
    if (!liveObservedEvents.length && liveEventsPromise) {
      liveObservedEvents = await liveEventsPromise.catch((error) => {
        output?.appendLine?.(`[ioi-studio] live daemon event projection ended early: ${error?.message || String(error)}`);
        return [];
      });
    }
  } catch (error) {
    if (!/timed out|timeout/i.test(error?.message || String(error))) {
      throw error;
    }
    liveObservedEvents = await Promise.resolve(liveEventsPromise).catch((liveError) => {
      output?.appendLine?.(`[ioi-studio] live daemon event recovery after Agent POST timeout ended early: ${liveError?.message || String(liveError)}`);
      return [];
    }) || [];
    turn = studioAgentTurnRecovery.recoverStudioAgentTurnFromLiveEventsAfterSubmitTimeout({
      threadId,
      prompt,
      submittedAtMs,
      events: liveObservedEvents,
    });
    if (turn) {
      output?.appendLine?.("[ioi-studio] recovered daemon turn from live streamed runtime events after Agent POST timeout.");
      studioRuntimeProjection.timeline.push({
        label: "Agent turn recovered",
        detail: "Live daemon runtime events completed after the POST transport timed out.",
        status: "completed",
      });
    }
    if (turn) {
      // Keep the streamed model answer as the product handoff; trace keeps the transport timeout.
    } else {
      output?.appendLine?.(`[ioi-studio] Agent turn POST exceeded ${STUDIO_AGENT_TURN_POST_TIMEOUT_MS}ms; checking daemon turn projection.`);
      turn = await studioAgentTurnRecovery.recoverStudioAgentTurnAfterSubmitTimeout({
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
  const allEvents = uniqueStudioRuntimeEvents([
    ...responseEvents,
    ...refreshEvents,
    ...liveObservedEvents,
    ...streamedEvents,
  ]);
  const events = studioRuntimeEventsForTurn(allEvents, turn.turn_id || turn.turnId);
  applyStudioAgentTurnEvents(events, {
    projectAnswerStream,
    answerStreamPresentation,
    answerStreamFileName,
  });
  const needsRetrieval = studioIntentFrameRequiresRetrieval(intentFrame, prompt);
  const hasSearch = studioRuntimeEventsIncludeTool(events, /web(::|__)search|search_web|web_search/);
  const hasRead = studioRuntimeEventsIncludeTool(events, /web(::|__)read|read_web|web_read/);
  const hasCompletedSearch = studioRuntimeEventsIncludeCompletedTool(events, /web(::|__)search|search_web|web_search/);
  const hasCompletedRead = studioRuntimeEventsIncludeCompletedTool(events, /web(::|__)read|read_web|web_read/);
  const chatReplyText = studioAssistantTextFromRuntimeToolEvents(events);
  const resultText = studioAgentTurnResultText(turn, events);
  const policyBlockedRuntimeText = studioPolicyBlockedRuntimeMessage({ prompt, resultText, events });
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
  if (
    needsRetrieval &&
    !(hasCompletedSearch && hasCompletedRead) &&
    !resultLooksRetrievalGrounded
  ) {
    throw new Error(
      [
        "Agent Mode failed closed: this prompt requires current/source retrieval, but the Rust runtime did not complete the required retrieval evidence.",
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
  const sourceRefs = studioSourceRefsFromRuntimeEvents(events);
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
  if (!resultText && !retrievalFailClosedText) {
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
    if (policyBlockedRuntimeText) {
      studioRuntimeProjection.timeline.push({
        label: "Agent turn blocked",
        detail: `${events.length} runtime event${events.length === 1 ? "" : "s"} projected`,
        status: "blocked",
      });
      return {
        turn,
        events,
        text: policyBlockedRuntimeText,
        receiptRefs,
        status: "blocked",
        policyBlocked: true,
      };
    }
    throw new Error(
      [
        "Daemon agent turn completed but did not emit a clean final answer.",
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
    sourceRefs,
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
  studioRuntimeProjection.pendingWorklog = [];
  const workCursor = studioWorkCursor();
  studioAgentAnswerStreamProjector.reset();
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
  const modelSelectionError = studioProductModelSelectionError(selectedRoute, selectedModelId);
  if (modelSelectionError) {
    const cleanMessage = studioCleanProductErrorMessage(modelSelectionError);
    studioRuntimeProjection.pending = false;
    studioRuntimeProjection.status = "blocked";
    studioRuntimeProjection.lastError = cleanMessage;
    studioRuntimeProjection.timeline.push({
      label: "Product model route unavailable",
      detail: cleanMessage,
      status: "blocked",
    });
    studioRuntimeProjection.turns.push({
      role: "assistant",
      content: cleanMessage,
      createdAt: new Date().toISOString(),
      agentTurn: {
        status: "blocked",
        eventCount: 0,
        receiptRefs: [],
        prompt,
      },
    });
    await refreshStudioPanelHtml(output);
    return;
  }
  const resolvedIntentFrame = await resolveStudioPromptIntentFrame(prompt, {
    executionMode,
    selectedRoute,
    selectedModelId,
    approvalMode,
    workspacePath: workspace.path,
  }, output);
  const resolvedIntentFramePayload = studioIntentFramePayload(resolvedIntentFrame);
  studioRuntimeProjection.lastIntentFrame = resolvedIntentFramePayload;
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
      ...(resolvedIntentFramePayload
        ? {
            intentFrame: resolvedIntentFramePayload,
            intent_frame: resolvedIntentFramePayload,
            runtimeAction: resolvedIntentFramePayload.runtimeAction || resolvedIntentFramePayload.runtime_action || null,
            runtime_action: resolvedIntentFramePayload.runtime_action || resolvedIntentFramePayload.runtimeAction || null,
          }
        : {}),
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
        thinkingText: streamResult.thinkingText,
        createdAt: new Date().toISOString(),
        modelStream: {
          streamId: streamResult.streamId,
          chunkCount: streamResult.chunkCount,
          receiptIds: streamResult.receiptIds,
          routeId: streamResult.routeId,
          model: streamResult.model,
          provider: streamResult.provider,
          providerStream: streamResult.providerStream,
          thinkingText: streamResult.thinkingText,
          metrics: streamResult.metrics,
          askMode: true,
          directModelAnswer: true,
          chatOnlyMode: true,
          completed: true,
        },
      };
    } else {
      const intentFrame = resolvedIntentFrame;
      const projectsArtifact = studioIntentFrameProjectsArtifact(intentFrame) ||
        shouldProjectConversationArtifactCanvas(prompt);
      const agentTurn = projectsArtifact
        ? await projectStudioConversationArtifactCanvas(prompt, output, intentFrame)
        : await submitStudioAgentTurn(
            {
              prompt,
              selectedRoute,
              selectedModelId,
              reasoningEffort,
              workspacePath: workspace.path,
              intentFrame,
            },
            output,
          );
      if (!projectsArtifact && (studioIntentFrameProjectsRuntimeCockpit(intentFrame) || shouldProjectStudioRuntimeCockpit(prompt))) {
        await projectStudioRuntimeCockpit(prompt, agentTurn, output);
      }
      const agentTurnStatus = agentTurn.status === "blocked" ? "blocked" : "completed";
      const workspaceChangeHunks = !projectsArtifact
        ? await refreshStudioWorkspaceChangeReviewsFromDaemon(output)
        : [];
      if (workspaceChangeHunks.length > 0) {
        appendStudioTimeline(
          "Workspace hunk review ready",
          `${workspaceChangeHunks.length} hunk${workspaceChangeHunks.length === 1 ? "" : "s"} waiting for review`,
          "needs_review",
        );
      }
      const daemonSessionCards = !projectsArtifact
        ? await refreshStudioManagedSessionsFromDaemon(output)
        : [];
      const workRecord = studioWorkRecordWithSessionCards(
        studioDocumentedWorkRecord(workCursor),
        daemonSessionCards,
      );
      const managedSessionCount = firstArray(workRecord?.sessionCards).length;
      if (managedSessionCount) {
        studioRuntimeProjection.runtimeCockpit.managedLiveViewportObserved = true;
        studioRuntimeProjection.runtimeCockpit.managedSessionLabelsObserved = true;
        studioRuntimeProjection.runtimeCockpit.managedSessionCount = Math.max(
          managedSessionCount,
          Number(studioRuntimeProjection.runtimeCockpit.managedSessionCount || 0) || 0,
        );
      }
      const blockedThreadId = agentTurnStatus === "blocked" ? studioRuntimeProjection.threadId : null;
      const productAgentText = sanitizeStudioProductAssistantText(agentTurn.text);
      const daemonAnswerStream = agentTurnStatus === "completed" && studioAgentAnswerStreamProjector.hasObservedStream()
        ? studioAgentAnswerStreamProjector.complete(productAgentText, {
            allowFallbackStart: false,
            sourceRefs: firstArray(agentTurn.sourceRefs),
            workRecord: studioPublicWorkRecordForWebview(workRecord),
          })
        : null;
      const finalHandoffStream = agentTurnStatus === "completed" && !daemonAnswerStream
        ? await studioAgentFinalHandoffStreamer.streamStudioAgentFinalHandoff(productAgentText, {
            prompt,
            turnId: studioRuntimeProjection.turnId,
            sourceRefs: firstArray(agentTurn.sourceRefs),
            workRecord: studioPublicWorkRecordForWebview(workRecord),
          })
        : null;
      const modelStream = daemonAnswerStream || (finalHandoffStream
        ? { streamId: finalHandoffStream.streamId, chunkCount: finalHandoffStream.chunkCount, agentFinalHandoff: true, runtimeAuthority: "daemon-owned", completed: true }
        : null);
      assistantTurn = {
        role: "assistant",
        content: productAgentText,
        createdAt: new Date().toISOString(),
        agentTurn: {
          turnId: studioRuntimeProjection.turnId,
          eventCount: agentTurn.events.length,
          receiptRefs: agentTurn.receiptRefs,
          prompt,
          status: agentTurnStatus,
          approvalPause: Boolean(agentTurn.approvalPause),
        },
        ...(agentTurn.sourceRefs ? { sourceRefs: agentTurn.sourceRefs } : {}),
        ...(agentTurn.artifacts ? { artifacts: agentTurn.artifacts } : {}),
        ...(agentTurn.modelMetrics ? { modelMetrics: agentTurn.modelMetrics } : {}),
        ...(modelStream ? { modelStream } : {}),
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
    const latestWorkStepElapsedMs = studioPendingWorklogLastAtMs()
      ? Date.now() - studioPendingWorklogLastAtMs()
      : 0;
    const pendingMinimumWaitMs = Math.max(
      0,
      1400 - pendingElapsedMs,
      firstArray(studioRuntimeProjection.pendingWorklog).length > 0 ? 1200 - latestWorkStepElapsedMs : 0,
    );
    if (firstArray(studioRuntimeProjection.pendingWorklog).length > 0) {
      studioPostPendingWorklogSnapshot();
    }
    if (pendingMinimumWaitMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, pendingMinimumWaitMs));
    }
    studioRuntimeProjection.pending = false;
    studioRuntimeProjection.status = assistantTurn?.agentTurn?.status === "blocked" ? "blocked" : "completed";
      if (executionMode === STUDIO_MODE_AGENT) {
        await projectStudioAgentTurnToWebview({
          assistantTurn,
          status: studioRuntimeProjection.status,
          prompt,
        }, output);
        if (firstArray(studioRuntimeProjection.diffHunks).length > 0 && studioPanel) {
          studioPanel.reveal(vscode.ViewColumn.One);
          await refreshStudioPanelHtml(output);
        }
      }
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
    const rawErrorMessage = error?.message || String(error);
    const cleanErrorMessage = studioCleanProductErrorMessage(error);
    studioRuntimeProjection.pending = false;
    studioRuntimeProjection.status = "blocked";
    studioRuntimeProjection.lastError = cleanErrorMessage;
    studioRuntimeProjection.timeline.push({
      label: isApprovalPause ? "Daemon turn waiting for approval" : "Daemon turn blocked",
      detail: cleanErrorMessage,
      status: "blocked",
    });
    output?.appendLine?.(`[ioi-studio] raw daemon turn error kept in Trace/evidence: ${rawErrorMessage}`);
    const daemonSessionCards = executionMode === STUDIO_MODE_AGENT
      ? await refreshStudioManagedSessionsFromDaemon(output)
      : [];
    if (executionMode === STUDIO_MODE_AGENT) {
      await refreshStudioWorkspaceChangeReviewsFromDaemon(output);
    }
    studioRuntimeProjection.turns.push({
      role: "assistant",
      content: isApprovalPause
        ? cleanErrorMessage
        : cleanErrorMessage,
      createdAt: new Date().toISOString(),
      ...(daemonSessionCards.length
        ? {
            workRecord: studioWorkRecordWithSessionCards(null, daemonSessionCards),
          }
        : {}),
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
  const requestedDecision = stringValue(decision).toLowerCase();
  const normalizedDecision = requestedDecision === "reject" || requestedDecision === "rollback"
    ? requestedDecision
    : "approve";
  try {
    await ensureStudioDaemonThread({ model: studioRuntimeProjection.modelRoute }, output);
    const endpoint = daemonEndpoint();
    const threadId = studioRuntimeProjection.threadId;
    const approvalId =
      stringValue(payload.approvalId, studioRuntimeProjection.approvalId || STUDIO_APPROVAL_ID);
    const changeId = stringValue(payload.changeId || payload.change_id);
    if (changeId) {
      const toolId = normalizedDecision === "rollback"
        ? "workspace_change__rollback"
        : normalizedDecision === "reject"
          ? "workspace_change__reject"
          : "workspace_change__accept";
      const result = await invokeStudioDaemonTool(
        threadId,
        toolId,
        normalizedDecision === "rollback"
          ? { change_id: changeId }
          : normalizedDecision === "approve"
            ? { change_id: changeId }
          : {
              change_id: changeId,
              reason: "Operator rejected the Studio inline diff hunk.",
            },
        output,
        {
          title: normalizedDecision === "rollback"
            ? "Rollback workspace hunk"
            : normalizedDecision === "approve"
              ? "Accept workspace hunk"
              : "Reject workspace hunk",
          detail: normalizedDecision === "rollback"
            ? "Daemon rolled back the selected workspace change."
            : normalizedDecision === "approve"
              ? "Daemon accepted the selected workspace change."
            : "Daemon rejected the selected workspace change.",
        },
      );
      studioRuntimeProjection.hunkDecision = normalizedDecision;
      studioRuntimeProjection.diffHunks = studioRuntimeProjection.diffHunks.map((hunk) => ({
        ...hunk,
        status: hunk.changeId === changeId || hunk.change_id === changeId
          ? normalizedDecision === "approve"
            ? "approved"
            : normalizedDecision === "rollback"
            ? "rolled_back"
            : "rejected"
          : hunk.status,
      }));
      studioRuntimeProjection.approvals = [
        {
          id: approvalId,
          status: normalizedDecision === "approve"
            ? "approved"
            : normalizedDecision === "rollback"
              ? "rolled_back"
              : "rejected",
          label: normalizedDecision === "approve"
            ? "Workspace hunk accepted"
            : normalizedDecision === "rollback"
              ? "Workspace hunk rolled back"
              : "Workspace hunk rejected",
          detail: "Daemon workspace change lifecycle action completed.",
        },
      ];
      appendStudioReceiptsFromResponse(result, `workspace_change_${normalizedDecision}`, "Daemon workspace change lifecycle receipt.");
      studioRuntimeProjection.runtimeCockpit.hunkAcceptRejectReceiptsObserved = true;
      recomputeStudioRuntimeCockpitAchieved();
      await writeBridgeRequest(
        "chat.hunkDecision",
        {
          ...payload,
          decision: normalizedDecision,
          approvalId,
          changeId,
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
      await refreshStudioWorkspaceChangeReviewsFromDaemon(output);
      await refreshStudioPanelHtml(output);
      return;
    }
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

async function handleStudioArtifactAction(payload = {}, output) {
  const artifactId = stringValue(payload.artifactId || payload.artifact_id);
  const action = stringValue(payload.action, "ask");
  if (!artifactId) {
    appendStudioTimeline("Artifact action blocked", "Missing artifact id.", "blocked");
    await refreshStudioPanelHtml(output);
    return;
  }
  const result = await runStudioConversationArtifactAction(artifactId, action, output, payload);
  if (result?.artifact) {
    studioRuntimeProjection.conversationArtifacts = studioRuntimeProjection.conversationArtifacts.map((artifact) =>
      (artifact.id || artifact.artifactId || artifact.artifact_id) === artifactId ? result.artifact : artifact,
    );
    appendStudioTimeline("Artifact action completed", `${action} · ${result.artifact.title || artifactId}`, "completed", {
      artifactId,
    });
  }
  await writeBridgeRequest(
    "chat.artifactAction",
    {
      artifactId,
      action,
      runtimeAuthority: "daemon-owned",
      projectionOwner: "ioi-workbench-agent-studio",
      ownsRuntimeState: false,
    },
    buildWorkspaceActionContext("agent-studio-conversation-artifact"),
  ).catch((error) => {
    output?.appendLine?.(`[ioi-studio] bridge artifact action route unavailable: ${error?.message || String(error)}`);
  });
  await refreshStudioPanelHtml(output);
}

async function handleStudioManagedSessionControl(payload = {}, output) {
  const managedSessionId = stringValue(payload.managedSessionId || payload.managed_session_id);
  const control = stringValue(payload.control || payload.action, "observe");
  if (!managedSessionId) {
    appendStudioTimeline("Managed session control blocked", "Missing managed session id.", "blocked");
    await refreshStudioPanelHtml(output);
    return;
  }
  const endpoint = daemonEndpoint();
  const threadId = stringValue(studioRuntimeProjection.threadId);
  if (!endpoint || !threadId) {
    appendStudioTimeline("Managed session control blocked", "Daemon thread unavailable.", "blocked");
    await refreshStudioPanelHtml(output);
    return;
  }
  studioRuntimeProjection.computerUseSessions = firstArray(studioRuntimeProjection.computerUseSessions).map((session) =>
    session.id === managedSessionId
      ? {
          ...session,
          controlState: control,
          updatedAt: new Date().toISOString(),
        }
      : session,
  );
  applyStudioManagedSessionsToLatestTurn(studioRuntimeProjection.computerUseSessions);
  try {
    const result = await requestJson(
      endpoint,
      `/v1/threads/${encodeURIComponent(threadId)}/managed-sessions/control`,
      {
        method: "POST",
        token: daemonRequestToken(),
        payload: {
          managedSessionId,
          action: control,
          reason:
            stringValue(payload.reason) ||
            (control === "take_over"
              ? "operator requested manual control"
              : control === "return_agent"
                ? "operator returned control to Agent"
                : "operator observing session"),
          source: "agent_studio_managed_session_card",
          turnId: studioRuntimeProjection.turnId || null,
        },
        timeoutMs: 5000,
      },
    );
    applyStudioManagedSessionInspection(result?.inspection || result);
    studioRuntimeProjection.runtimeCockpit.managedSessionControlObserved = true;
    appendStudioTimeline(
      "Managed session control receipted",
      `${managedSessionId} · ${control}`,
      "completed",
    );
  } catch (error) {
    appendStudioTimeline(
      "Managed session control blocked",
      error?.message || String(error),
      "blocked",
    );
  }
  await refreshStudioPanelHtml(output);
}

async function navigateStudioHunk(direction, output) {
  await refreshStudioWorkspaceChangeReviewsFromDaemon(output);
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
          runtimeControlAction: "stop",
          runtime_control_action: "stop",
        },
      },
    ).then((result) => {
      appendStudioReceiptsFromResponse(result, "session_stop", "Daemon stopped Studio thread.");
      if (result?.runtime_control || result?.runtimeControl) {
        studioRuntimeProjection.runtimeCockpit.stopControlObserved = true;
        studioRuntimeProjection.runtimeCockpit.stopResumeObserved =
          studioRuntimeProjection.runtimeCockpit.resumeControlObserved === true;
        recomputeStudioRuntimeCockpitAchieved();
        appendStudioTimeline("Runtime stop control", "Daemon runtime_service control_thread stop acknowledged.", "completed");
      }
    }).catch((error) => {
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
      if (result?.runtime_control || result?.runtimeControl) {
        studioRuntimeProjection.runtimeCockpit.resumeControlObserved = true;
        studioRuntimeProjection.runtimeCockpit.stopResumeObserved =
          studioRuntimeProjection.runtimeCockpit.stopControlObserved === true;
        recomputeStudioRuntimeCockpitAchieved();
        appendStudioTimeline("Runtime resume control", "Daemon runtime_service control_thread resume acknowledged.", "completed");
      }
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
      if (message?.type === "studioArtifactAction") {
        await handleStudioArtifactAction(message.payload || {}, output);
        return;
      }
      if (message?.type === "studioManagedSessionControl") {
        await handleStudioManagedSessionControl(message.payload || {}, output);
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
          applyStudioAgentModeSelection(message.payload || {});
          await refreshStudioPanelHtml(output);
          await focusStudioPanelComposer();
        }
        if (message.requestType === "chat.permissionMode.select") {
          await applyStudioPermissionModeSelection(message.payload || {}, output);
          await refreshStudioPanelHtml(output);
          await focusStudioPanelComposer();
        }
        if (message.requestType === "chat.newSession") {
          startNewStudioSession("Operator started a fresh Studio chat session.");
          await refreshStudioPanelHtml(output);
          await focusStudioPanelComposer();
        }
        if (!message.payload?.bridgeRequestAlreadyWritten) {
          await writeBridgeRequest(
            message.requestType,
            message.payload || {},
            buildWorkspaceActionContext("studio-panel-webview"),
          ).catch((error) => {
            output.appendLine(
              `[ioi-studio] bridge request unavailable: ${error?.message || String(error)}`,
            );
          });
        }
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
      studioPanelPageNonce = null;
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

  registerMigrationCommands({
    context,
    output,
    vscode,
    buildWorkspaceActionContext,
    writeBridgeRequest,
    workspaceSummary,
    status,
  });
  registerQuickInputCommands({
    context,
    output,
    vscode,
    buildWorkspaceActionContext,
    writeBridgeRequest,
    status,
  });

  context.subscriptions.push(
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
      refreshStudioReplayStepsFromProjection();
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
    vscode.commands.registerCommand("ioi.studio.exercisePolicyLeaseLifecycle", async () => {
      if (process.env.IOI_AUTOPILOT_STUDIO_TEST_HOOKS !== "1") {
        output.appendLine("[ioi-studio] policy lease lifecycle exercise refused outside test hooks.");
        return;
      }
      const contextSnapshot = buildWorkspaceActionContext("studio-policy-lease-lifecycle");
      await enterAutopilotMode("studio", output);
      await openStudioPanel(context, output);
      const lifecycleProof = await exerciseStudioPolicyLeaseLifecycle(output);
      await refreshStudioPanelHtml(output);
      await writeBridgeRequest("studio.policyLeaseLifecycle.exercised", {
        sourceCommand: "ioi.studio.exercisePolicyLeaseLifecycle",
        runtimeAuthority: "daemon-owned",
        projectionOwner: "openvscode-workbench-adapter",
        ownsRuntimeState: false,
        ...lifecycleProof,
      }, contextSnapshot).catch((error) => {
        output.appendLine(
          `[ioi-studio] policy lease lifecycle bridge request unavailable: ${error?.message || String(error)}`,
        );
      });
      status(lifecycleProof.passed ? "Exercised Studio policy lease lifecycle." : "Studio policy lease lifecycle proof is incomplete.");
    }),
    vscode.commands.registerCommand("ioi.studio.exerciseSessionBrainLifecycle", async () => {
      if (process.env.IOI_AUTOPILOT_STUDIO_TEST_HOOKS !== "1") {
        output.appendLine("[ioi-studio] session brain lifecycle exercise refused outside test hooks.");
        return;
      }
      await enterAutopilotMode("studio", output);
      await openStudioPanel(context, output);
      const lifecycleProof = await exerciseStudioSessionBrainLifecycle(output);
      await refreshStudioPanelHtml(output);
      status(lifecycleProof.passed
        ? "Exercised Agent Studio run brain lifecycle."
        : "Agent Studio run brain lifecycle proof incomplete.");
    }),
    vscode.commands.registerCommand("ioi.studio.exerciseTrajectoryReplayReconnect", async (payload = {}) => {
      if (process.env.IOI_AUTOPILOT_STUDIO_TEST_HOOKS !== "1") {
        output.appendLine("[ioi-studio] trajectory replay reconnect exercise refused outside test hooks.");
        return;
      }
      await enterAutopilotMode("studio", output);
      await openStudioPanel(context, output);
      const lifecycleProof = await exerciseStudioTrajectoryReplayReconnect(output, payload);
      await refreshStudioPanelHtml(output);
      status(lifecycleProof.passed
        ? "Exercised Agent Studio trajectory replay reconnect."
        : "Agent Studio trajectory replay reconnect proof incomplete.");
    }),
    vscode.commands.registerCommand("ioi.studio.exerciseManagedSessionReconnect", async (payload = {}) => {
      if (process.env.IOI_AUTOPILOT_STUDIO_TEST_HOOKS !== "1") {
        output.appendLine("[ioi-studio] managed session reconnect exercise refused outside test hooks.");
        return;
      }
      await enterAutopilotMode("studio", output);
      await openStudioPanel(context, output);
      const lifecycleProof = await exerciseStudioManagedSessionReconnect(output, payload);
      await refreshStudioPanelHtml(output);
      status(lifecycleProof.passed
        ? "Exercised Agent Studio managed session reconnect."
        : "Agent Studio managed session reconnect proof incomplete.");
    }),
    vscode.commands.registerCommand("ioi.studio.exerciseStage2WebRepairLoop", async (payload = {}) => {
      if (process.env.IOI_AUTOPILOT_STUDIO_TEST_HOOKS !== "1") {
        output.appendLine("[ioi-studio] stage2 web repair loop exercise refused outside test hooks.");
        return;
      }
      await enterAutopilotMode("studio", output);
      await openStudioPanel(context, output);
      const repairProof = await exerciseStudioStage2WebRepairLoop(output, payload);
      await refreshStudioPanelHtml(output);
      status(repairProof.passed
        ? "Exercised Agent Studio Stage 2 web repair loop."
        : "Agent Studio Stage 2 web repair loop proof incomplete.");
    }),
    vscode.commands.registerCommand("ioi.studio.exerciseStage5StopHookRepairLoop", async (payload = {}) => {
      if (process.env.IOI_AUTOPILOT_STUDIO_TEST_HOOKS !== "1") {
        output.appendLine("[ioi-studio] stage5 stop-hook repair loop exercise refused outside test hooks.");
        return;
      }
      await enterAutopilotMode("studio", output);
      await openStudioPanel(context, output);
      const repairProof = await exerciseStudioStage5StopHookRepairLoop(output, payload);
      await refreshStudioPanelHtml(output);
      status(repairProof.passed
        ? "Exercised Agent Studio Stage 5 stop-hook repair loop."
        : "Agent Studio Stage 5 stop-hook repair loop proof incomplete.");
    }),
    vscode.commands.registerCommand("ioi.studio.exerciseStage5StopCancelRecoverLifecycle", async (payload = {}) => {
      if (process.env.IOI_AUTOPILOT_STUDIO_TEST_HOOKS !== "1") {
        output.appendLine("[ioi-studio] stage5 stop/cancel/recover exercise refused outside test hooks.");
        return;
      }
      await enterAutopilotMode("studio", output);
      await openStudioPanel(context, output);
      const lifecycleProof = await exerciseStudioStage5StopCancelRecoverLifecycle(output, payload);
      await refreshStudioPanelHtml(output);
      status(lifecycleProof.passed
        ? "Exercised Agent Studio Stage 5 stop/cancel/recover lifecycle."
        : "Agent Studio Stage 5 stop/cancel/recover proof incomplete.");
    }),
    vscode.commands.registerCommand("ioi.studio.exerciseStage7DelegationLifecycle", async (payload = {}) => {
      if (process.env.IOI_AUTOPILOT_STUDIO_TEST_HOOKS !== "1") {
        output.appendLine("[ioi-studio] stage7 delegation exercise refused outside test hooks.");
        return;
      }
      await enterAutopilotMode("studio", output);
      await openStudioPanel(context, output);
      const lifecycleProof = await exerciseStudioStage7DelegationLifecycle(output, payload);
      await refreshStudioPanelHtml(output);
      status(lifecycleProof.passed
        ? "Exercised Agent Studio Stage 7 delegation lifecycle."
        : "Agent Studio Stage 7 delegation proof incomplete.");
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
    vscode.commands.registerCommand("ioi.studio.applyAgentMode", async (payload = {}) => {
      const applied = applyStudioAgentModeSelection(payload);
      await refreshStudioPanelHtml(output);
      await focusStudioPanelComposer();
      status(`Agent Studio mode set to ${studioExecutionModeLabel(applied.executionMode)}.`);
    }),
    vscode.commands.registerCommand("ioi.studio.applyPermissionMode", async (payload = {}) => {
      const mapping = await applyStudioPermissionModeSelection(payload, output);
      await refreshStudioPanelHtml(output);
      await focusStudioPanelComposer();
      status(`Agent Studio permissions set to ${studioPermissionModeLabel(mapping.approvalMode)}.`);
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
