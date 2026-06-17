"use strict";

function createWorkflowComposerPanelRenderer({
  hypervisorShellHeaderStyles,
  bridgeUrl,
  daemonEndpoint,
  daemonToken,
  escapeHtml,
  nonce,
  renderHypervisorShellHeader,
  vscode,
  workspaceSummary,
}) {
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
      daemonModelId: process.env.IOI_DAEMON_MODEL_ID || process.env.IOI_HYPERVISOR_MODEL_ID || null,
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
      ${hypervisorShellHeaderStyles()}
    </style>
    <title>Hypervisor Workflow Composer</title>
  </head>
  <body class="workflow-composer-shell">
    ${renderHypervisorShellHeader({ workspace: workspaceSummary(), modelMounting: {}, runs: [], policy: {} }, "workflows")}
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

  return {
    workflowComposerHtml,
  };
}

module.exports = {
  createWorkflowComposerPanelRenderer,
};
