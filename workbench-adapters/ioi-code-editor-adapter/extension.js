"use strict";

const vscode = require("vscode");
const { bridgeUrl } = require("./bridge/client");
const { createCodeEditorAdapterBridge } = require("./bridge/workspace-bridge");
const {
  buildWorkspaceActionContext: buildWorkspaceActionContextFromEditor,
} = require("./editor-context/action-context");
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

function buildWorkspaceActionContext(source, uri) {
  return buildWorkspaceActionContextFromEditor({ vscode, workspaceSummary }, source, uri);
}

async function openCodeAdapter() {
  await writeBridgeRequest(
    "code.open",
    {
      workspaceRoot: workspaceSummary().path,
      sourceCommand: "ioi.code.open",
      runtimeAuthority: "daemon-owned",
      projectionOwner: "hypervisor-code-editor-adapter",
      ownsRuntimeState: false,
      vscodeSubstrateVisible: true,
    },
    buildWorkspaceActionContext("code-editor-adapter"),
  ).catch(() => undefined);

  await vscode.commands.executeCommand("workbench.view.explorer").catch(() => undefined);
}

function registerAdapterCommands(context, output) {
  const status = (message) => {
    vscode.window.setStatusBarMessage(`$(symbol-keyword) ${message}`, 3_000);
  };

  context.subscriptions.push(
    vscode.commands.registerCommand("ioi.code.open", async () => {
      await openCodeAdapter();
      status("Code editor adapter active.");
    }),
  );

  output.appendLine("Registered IOI code editor adapter commands.");
}

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

  registerAdapterCommands(context, output);

  const statusItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    80,
  );
  statusItem.name = "IOI Code Adapter";
  statusItem.text = "$(symbol-keyword) IOI";
  statusItem.tooltip = "Activate IOI Code Adapter.";
  statusItem.command = "ioi.code.open";
  statusItem.show();
  context.subscriptions.push(statusItem);
}

function deactivate() {}

module.exports = {
  activate,
  deactivate,
  workspaceSummary,
};
