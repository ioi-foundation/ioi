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

// M08.12 (R-214): a Hypervisor challenge notification, when the relay hands one to this host, renders as
// one warning message with the actions that open the operator's decision on the App. The renderer is
// VS-Code-free and unit-tested; this host only shows it and opens the chosen link. Nothing here approves.
const { renderChallengeNotification } = require("./editor-context/challenge-notification.js");
async function showChallengeNotification(vscode, notification) {
  const rendered = renderChallengeNotification(notification);
  if (!rendered.ok) return rendered;
  const picked = await vscode.window.showWarningMessage(rendered.message, ...rendered.actions.map((a) => a.title));
  const action = rendered.actions.find((a) => a.title === picked);
  if (action) await vscode.env.openExternal(vscode.Uri.parse(action.url));
  return rendered;
}
module.exports.showChallengeNotification = showChallengeNotification;
