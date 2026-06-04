import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createWorkbenchOverviewPanelRenderer } = require("./overview-panel.js");

function escapeHtml(value = "") {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function commandPayloadAttr(payload) {
  return payload ? ` data-payload="${escapeHtml(JSON.stringify(payload))}"` : "";
}

function createRenderer({ nonceValue = "overview-nonce", daemon = "http://127.0.0.1:1234" } = {}) {
  return createWorkbenchOverviewPanelRenderer({
    autopilotShellHeaderStyles: () => ".autopilot-shell{}",
    currentOverviewPanelNonce: () => nonceValue,
    daemonEndpoint: () => daemon,
    escapeHtml,
    loadedProductStudioModelInstances: () => [{ id: "loaded-1" }],
    modelSnapshotFromState: (state) => state.snapshot || { receipts: [] },
    overviewPill: (label, value, tone) =>
      `<span class="overview-pill is-${escapeHtml(tone)}"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></span>`,
    overviewTone: (value) => /connected|ready/i.test(String(value)) ? "ready" : "muted",
    productStudioModelSelectionsFromSnapshot: () => [{ id: "model-1" }, { id: "model-2" }],
    renderAutopilotShellHeader: () => `<header data-testid="autopilot-shell-header">Shell</header>`,
    renderOverviewAction: ({ label, description, command, payload, tone = "default" }) =>
      `<button class="overview-action is-${escapeHtml(tone)}" data-command="${escapeHtml(command)}"${commandPayloadAttr(payload)}><span>${escapeHtml(label)}</span><small>${escapeHtml(description)}</small></button>`,
    renderOverviewRow: (label, value, detail, tone = "muted") =>
      `<div class="overview-row"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong><small class="is-${escapeHtml(tone)}">${escapeHtml(detail)}</small></div>`,
    workspaceSummary: () => ({ name: "Fallback workspace", path: "/fallback" }),
  });
}

test("overview panel preserves nonce wiring, daemon ownership, and command affordances", () => {
  const renderer = createRenderer();
  const html = renderer.overviewPanelHtml({
    workspace: { name: "Repo", path: "/workspace/repo" },
    modelMountingStatus: { status: "connected", endpoint: "local daemon" },
  });

  assert.match(html, /style-src 'nonce-overview-nonce'/);
  assert.match(html, /script-src 'nonce-overview-nonce'/);
  assert.match(html, /<style nonce="overview-nonce">/);
  assert.match(html, /<script nonce="overview-nonce">/);
  assert.match(html, /data-testid="autopilot-overview-home"/);
  assert.match(html, /data-runtime-authority="daemon-owned"/);
  assert.match(html, /data-testid="autopilot-shell-header"/);
  assert.match(html, /data-command="ioi\.studio\.open"/);
  assert.match(html, /data-command="ioi\.workflow\.openComposer"/);
  assert.match(html, /data-command="ioi\.models\.open"/);
  assert.match(html, /data-command="ioi\.policy\.open"/);
  assert.match(html, /data-command="ioi\.connections\.inspect"/);
  assert.match(html, /&quot;scenarioId&quot;:&quot;connector-fixture&quot;/);
});

test("overview panel escapes workspace and projected item text", () => {
  const renderer = createRenderer();
  const html = renderer.overviewPanelHtml({
    workspace: { name: "Repo <main>", path: "/workspace/repo&main" },
    workflows: [{ name: "Workflow <x>", status: "ready&waiting" }],
    runs: [{ name: "Run <active>", status: "running" }],
    artifacts: [{ id: "artifact <id>", status: "pending&clean" }],
    snapshot: { receipts: [{ receiptId: "receipt <one>" }] },
  });

  assert.match(html, /Repo &lt;main&gt;/);
  assert.match(html, /\/workspace\/repo&amp;main/);
  assert.match(html, /Workflow &lt;x&gt;/);
  assert.match(html, /ready&amp;waiting/);
  assert.match(html, /Run &lt;active&gt;/);
  assert.match(html, /receipt &lt;one&gt;/);
  assert.doesNotMatch(html, /Repo <main>/);
});

test("overview panel projects disconnected daemon and empty evidence posture", () => {
  const renderer = createRenderer({ daemon: "" });
  const html = renderer.overviewPanelHtml({
    workspace: { name: "", path: "" },
    summary: { connectorCount: 3, policyIssueCount: 2 },
    connections: [{ status: "ready" }, { status: "blocked" }],
    snapshot: { receipts: [] },
  });

  assert.match(html, /daemon endpoint not configured/);
  assert.match(html, /No workspace selected/);
  assert.match(html, /Open a workspace folder to ground runtime context\./);
  assert.match(html, /1\/2 ready/);
  assert.match(html, /Receipts pending/);
  assert.match(html, /2 issues/);
});
