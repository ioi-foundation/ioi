"use strict";

const crypto = require("crypto");

function createWorkbenchContextSnapshot({
  vscode,
  workspaceSummary,
  buildRuntimeRefs,
  refSafe,
}) {
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
    } catch {
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

  function setLastTaskExitCode(value) {
    lastTaskExitCode = value;
  }

  return {
    activeEditorRef,
    buildWorkbenchContextSnapshot,
    buildWorkbenchInspectionTargetIndex,
    buildWorkbenchScmState,
    buildWorkbenchTaskState,
    diagnosticSeverityLabel,
    getLastTaskExitCode: () => lastTaskExitCode,
    rememberRecentTaskLabel,
    selectedTextHash,
    setLastTaskExitCode,
    toWorkbenchRange,
    uriToRef,
  };
}

module.exports = {
  createWorkbenchContextSnapshot,
};
