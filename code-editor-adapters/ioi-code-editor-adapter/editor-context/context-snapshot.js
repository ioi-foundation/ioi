"use strict";

const crypto = require("crypto");

function createCodeEditorContextSnapshot({
  vscode,
  workspaceSummary,
  buildRuntimeRefs,
}) {
  function toCodeEditorRange(range) {
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

  function buildCodeEditorScmState(openEditors) {
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

  function activeEditorRef(editor) {
    if (!editor) {
      return null;
    }
    const selection = editor.selection && !editor.selection.isEmpty
      ? toCodeEditorRange(editor.selection)
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

  function buildCodeEditorContextSnapshot(reason = "poll") {
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
          range: toCodeEditorRange(entry.range),
        })),
      );

    return {
      schemaVersion: "ioi.code-editor-adapter.v1",
      snapshotId: crypto.randomUUID(),
      runtimeTruthSource: "daemon-runtime",
      projectionOwner: "hypervisor-code-editor-adapter",
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
      scmState: buildCodeEditorScmState(openEditors),
      visibleView: {
        activeTextEditorVisible: Boolean(activeEditor),
        activeTabCount: openEditors.length,
        adapterKind: "code-editor",
        activityId: null,
        sideBarViewId: null,
        panelViewId: null,
        activeEditorGroup: activeEditor ? "active" : null,
        activeIoiViewId: null,
      },
      inspectionTargetIndexRef: "code-editor-target-index:latest",
      runtimeRefs: buildRuntimeRefs(),
    };
  }

  function buildCodeEditorInspectionTargetIndex(reason = "poll") {
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
                range: toCodeEditorRange(activeEditor.selection),
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
                range: toCodeEditorRange(activeEditor.selection),
              },
            ],
            fallbackAllowed: true,
          },
        ]
      : [];
    return {
      schemaVersion: "ioi.code-editor-adapter.v1",
      indexId: "code-editor-target-index:latest",
      runtimeTruthSource: "daemon-runtime",
      projectionOwner: "hypervisor-code-editor-adapter",
      ownsRuntimeState: false,
      generatedAtMs: Date.now(),
      reason,
      runtimeRefs: buildRuntimeRefs(),
      targets: [
        ...openEditorTargets,
        ...activeEditorTarget,
      ],
    };
  }

  return {
    activeEditorRef,
    buildCodeEditorContextSnapshot,
    buildCodeEditorInspectionTargetIndex,
    buildCodeEditorScmState,
    diagnosticSeverityLabel,
    selectedTextHash,
    toCodeEditorRange,
    uriToRef,
  };
}

module.exports = {
  createCodeEditorContextSnapshot,
};
