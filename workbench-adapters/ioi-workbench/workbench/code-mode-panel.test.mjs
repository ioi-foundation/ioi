import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createWorkbenchCodeModePanelRenderer } = require("./code-mode-panel.js");

function escapeHtml(value = "") {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function createRenderer({
  workspace = { path: "/workspace/current", name: "Current <repo>" },
  nonceValue = "nonce-1",
} = {}) {
  return createWorkbenchCodeModePanelRenderer({
    autopilotShellHeaderStyles: () => ".shell-header{}",
    buildWorkbenchContextSnapshot: (target) => ({
      target,
      workspace,
    }),
    escapeHtml,
    nonce: () => nonceValue,
    workspaceSummary: () => ({ path: "/fallback/workspace", name: "Fallback" }),
  });
}

test("code mode panel projects the current workspace as a repository row", () => {
  const renderer = createRenderer();
  const projection = renderer.codeRepositoryGateProjection({});

  assert.equal(projection.context.target, "code-repositories-gate");
  assert.deepEqual(projection.repositories, [{
    id: "current-workspace",
    name: "Current <repo>",
    rootPath: "/workspace/current",
    description: "Current Autopilot workspace",
    favorite: false,
  }]);
  assert.equal(renderer.relativeWorkspacePath("/workspace", "/workspace/current/file.txt"), "current/file.txt");
  assert.equal(renderer.shortPathLabel("/workspace/current"), "current");
});

test("code mode panel preserves command affordances, test ids, and escaping", () => {
  const renderer = createRenderer();
  const html = renderer.codeModePanelHtml({});

  assert.match(html, /data-testid="autopilot-code-mode"/);
  assert.match(html, /data-testid="code-repositories-gate"/);
  assert.match(html, /data-testid="code-mode-vscode-menu-tooling"/);
  assert.match(html, /data-command="ioi\.autopilot\.back"/);
  assert.match(html, /data-command="workbench\.view\.explorer"/);
  assert.match(html, /data-command="workbench\.action\.files\.openFolder"/);
  assert.match(html, /data-command="ioi\.commandCenter\.open"/);
  assert.match(html, /Current &lt;repo&gt;/);
  assert.doesNotMatch(html, /Current <repo>/);
});

test("code mode panel keeps CSP nonce and empty repository fallbacks stable", () => {
  const renderer = createRenderer({
    workspace: { path: "", name: "" },
    nonceValue: "nonce-xyz",
  });
  const html = renderer.codeModePanelHtml({});

  assert.match(html, /style-src 'nonce-nonce-xyz'/);
  assert.match(html, /script-src 'nonce-nonce-xyz'/);
  assert.match(html, /<style nonce="nonce-xyz">/);
  assert.match(html, /<script nonce="nonce-xyz">/);
  assert.match(html, /No recent activity/);
  assert.match(html, /You have no favorites/);
});
