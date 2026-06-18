"use strict";

const vscode = require("vscode");
const {
  bridgeUrl,
  readDaemonModelSnapshot,
} = require("./bridge/client");
const { createWorkspaceBridge } = require("./bridge/workspace-bridge");
const {
  buildWorkspaceActionContext: buildWorkspaceActionContextFromWorkbench,
} = require("./workbench/action-context");
const {
  startWorkbenchContextSnapshotPublisher,
} = require("./workbench/context-publisher");
const {
  createWorkbenchContextSnapshot,
} = require("./workbench/context-snapshot");

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

const workspaceBridge = createWorkspaceBridge({
  bridgeUrl,
  readDaemonModelSnapshot,
  workspaceSummary,
  vscode,
  modelSnapshotTimeoutMs: 1_000,
  refreshStateTimeoutMs: 1_000,
});

const {
  buildRuntimeRefs,
  startBridgeCommandPolling,
  writeBridgeRequest,
} = workspaceBridge;

const workbenchContext = createWorkbenchContextSnapshot({
  vscode,
  workspaceSummary,
  buildRuntimeRefs,
  refSafe,
});

function buildWorkspaceActionContext(source, uri) {
  return buildWorkspaceActionContextFromWorkbench({ vscode, workspaceSummary }, source, uri);
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

  startBridgeCommandPolling(context, output);
  startWorkbenchContextSnapshotPublisher({
    context,
    output,
    vscode,
    buildWorkbenchContextSnapshot: workbenchContext.buildWorkbenchContextSnapshot,
    buildWorkbenchInspectionTargetIndex: workbenchContext.buildWorkbenchInspectionTargetIndex,
    writeBridgeRequest,
    rememberRecentTaskLabel: workbenchContext.rememberRecentTaskLabel,
    getLastTaskExitCode: workbenchContext.getLastTaskExitCode,
    setLastTaskExitCode: workbenchContext.setLastTaskExitCode,
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
