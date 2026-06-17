import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createWorkflowComposerPanelRenderer } = require("./workflow-composer-panel.js");

function escapeHtml(value = "") {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function createRenderer({
  bridge = "http://127.0.0.1:7788",
  daemon = "http://127.0.0.1:9911/path?<bad>",
  token = "token-1",
  workspacePath = "/workspace/main",
} = {}) {
  const joined = [];
  const renderer = createWorkflowComposerPanelRenderer({
    hypervisorShellHeaderStyles: () => ".hypervisor-shell{}",
    bridgeUrl: () => bridge,
    daemonEndpoint: () => daemon,
    daemonToken: () => token,
    escapeHtml,
    nonce: () => "composer-nonce",
    renderHypervisorShellHeader: (state, modeId) =>
      `<header data-testid="hypervisor-shell-header" data-mode="${escapeHtml(modeId)}">${escapeHtml(state.workspace.path)}</header>`,
    vscode: {
      Uri: {
        joinPath: (...parts) => {
          joined.push(parts);
          return parts.map((part) => String(part?.path || part)).join("/");
        },
      },
    },
    workspaceSummary: () => ({ name: "Workspace", path: workspacePath }),
  });
  return { joined, renderer };
}

function createContextAndWebview() {
  return {
    context: { extensionUri: { path: "/extension" } },
    webview: {
      cspSource: "vscode-resource:",
      asWebviewUri: (uri) => `webview://${String(uri).replace(/^\/+/, "")}`,
    },
  };
}

test("workflow composer renderer preserves assets, nonce, shell header, and CSP sources", () => {
  const { renderer, joined } = createRenderer();
  const { context, webview } = createContextAndWebview();
  const html = renderer.workflowComposerHtml(context, webview);

  assert.match(html, /<title>Autopilot Workflow Composer<\/title>/);
  assert.match(html, /<link nonce="composer-nonce" rel="stylesheet" href="webview:\/\/extension\/media\/workflow-composer\/workflow-composer\.css"/);
  assert.match(html, /<script nonce="composer-nonce" type="module" src="webview:\/\/extension\/media\/workflow-composer\/workflow-composer\.js"/);
  assert.match(html, /script-src 'nonce-composer-nonce'/);
  assert.match(html, /connect-src vscode-resource: http:\/\/127\.0\.0\.1:9911\/path\?&lt;bad&gt; http:\/\/127\.0\.0\.1:\* http:\/\/localhost:\*/);
  assert.match(html, /data-testid="hypervisor-shell-header"/);
  assert.match(html, /data-mode="workflows"/);
  assert.equal(joined.length, 2);
});

test("workflow composer renderer serializes daemon-owned initial state safely", () => {
  const oldModelId = process.env.IOI_DAEMON_MODEL_ID;
  const oldAutopilotModelId = process.env.IOI_HYPERVISOR_MODEL_ID;
  process.env.IOI_DAEMON_MODEL_ID = "model<one>";
  delete process.env.IOI_HYPERVISOR_MODEL_ID;
  try {
    const { renderer } = createRenderer({
      bridge: "",
      daemon: "",
      token: "token<redacted>",
      workspacePath: "/workspace/<main>",
    });
    const { context, webview } = createContextAndWebview();
    const html = renderer.workflowComposerHtml(context, webview);

    assert.match(html, /window\.__IOI_WORKFLOW_COMPOSITOR_INITIAL_STATE__/);
    assert.match(html, /"workspaceRoot":"\/workspace\/\\u003cmain>"/);
    assert.match(html, /"bridgeConfigured":false/);
    assert.match(html, /"daemonEndpoint":""/);
    assert.match(html, /"daemonToken":"token\\u003credacted>"/);
    assert.match(html, /"daemonModelId":"model\\u003cone>"/);
    assert.match(html, /"runtimeAuthority":"daemon-owned"/);
    assert.match(html, /"projectionOwner":"ioi-workbench-workflow-composer-webview"/);
    assert.match(html, /"tauriUsed":false/);
    assert.doesNotMatch(html, /\/workspace\/<main>/);
  } finally {
    if (oldModelId === undefined) {
      delete process.env.IOI_DAEMON_MODEL_ID;
    } else {
      process.env.IOI_DAEMON_MODEL_ID = oldModelId;
    }
    if (oldAutopilotModelId === undefined) {
      delete process.env.IOI_HYPERVISOR_MODEL_ID;
    } else {
      process.env.IOI_HYPERVISOR_MODEL_ID = oldAutopilotModelId;
    }
  }
});
