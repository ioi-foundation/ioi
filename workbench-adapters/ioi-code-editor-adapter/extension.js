"use strict";

const vscode = require("vscode");
const { bridgeUrl } = require("./bridge/client");
const { createCodeEditorAdapterBridge } = require("./bridge/workspace-bridge");
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

function refSafe(value) {
  return String(value ?? "unknown").replace(/[^a-z0-9._:-]+/gi, "-");
}

const workspaceBridge = createCodeEditorAdapterBridge({
  bridgeUrl,
});

const {
  buildRuntimeRefs,
  writeBridgeRequest,
} = workspaceBridge;

const editorContext = createCodeEditorContextSnapshot({
  vscode,
  workspaceSummary,
  buildRuntimeRefs,
  refSafe,
});

function activate(context) {
  const output = vscode.window.createOutputChannel("IOI Code Adapter");
  output.appendLine("IOI Code Adapter extension activated.");
  context.subscriptions.push(output);

  startCodeEditorContextPublisher({
    context,
    output,
    vscode,
    buildCodeEditorContextSnapshot: editorContext.buildCodeEditorContextSnapshot,
    buildCodeEditorInspectionTargetIndex: editorContext.buildCodeEditorInspectionTargetIndex,
    writeBridgeRequest,
    rememberRecentTaskLabel: editorContext.rememberRecentTaskLabel,
    getLastTaskExitCode: editorContext.getLastTaskExitCode,
    setLastTaskExitCode: editorContext.setLastTaskExitCode,
  });

  const statusItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    80,
  );
  statusItem.name = "IOI Code Adapter";
  statusItem.text = "$(symbol-keyword) IOI";
  statusItem.tooltip = "IOI Code Adapter publishes editor context to Hypervisor.";
  statusItem.show();
  context.subscriptions.push(statusItem);
}

function deactivate() {}

module.exports = {
  activate,
  deactivate,
  workspaceSummary,
};
