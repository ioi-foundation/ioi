"use strict";

const vscode = require("vscode");
const { transportUrl } = require("./transport/client");
const { createCodeEditorAdapterTransport } = require("./transport/context-transport");
const {
  startCodeEditorContextPublisher,
} = require("./editor-context/context-publisher");
const {
  createCodeEditorContextSnapshot,
} = require("./editor-context/context-snapshot");

function workspaceSummary() {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    return {
      name: "No folder",
      path: "Open a workspace folder to ground Hypervisor context.",
    };
  }

  return {
    name: folder.name,
    path: folder.uri.fsPath,
  };
}

const contextTransport = createCodeEditorAdapterTransport({
  transportUrl,
});

const {
  buildRuntimeRefs,
  writeContextEnvelope,
} = contextTransport;

const editorContext = createCodeEditorContextSnapshot({
  vscode,
  workspaceSummary,
  buildRuntimeRefs,
});

function activate(context) {
  startCodeEditorContextPublisher({
    context,
    vscode,
    buildCodeEditorContextSnapshot: editorContext.buildCodeEditorContextSnapshot,
    buildCodeEditorInspectionTargetIndex: editorContext.buildCodeEditorInspectionTargetIndex,
    writeContextEnvelope,
    reportError: (error) => {
      console.warn(
        "[IOI Code Editor Adapter] Context snapshot failed:",
        error?.message || String(error),
      );
    },
  });
}

function deactivate() {}

module.exports = {
  activate,
  deactivate,
  workspaceSummary,
};
