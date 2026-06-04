import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createWorkbenchModeBodyRenderers } = require("./mode-body-renderers.js");

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

function createRenderers() {
  return createWorkbenchModeBodyRenderers({
    escapeHtml,
    formatRelativeTime: (timestampMs) => timestampMs ? "5m ago" : "now",
    renderCommandButton: (action) =>
      `<button class="action" data-command="${escapeHtml(action.command)}"${commandPayloadAttr(action.payload)}>${escapeHtml(action.label)}</button>`,
    renderItems: (items, emptyLabel, renderItem) =>
      items.length ? `<div class="stack">${items.map(renderItem).join("")}</div>` : `<div class="empty-state">${escapeHtml(emptyLabel)}</div>`,
  });
}

test("mode body renderers keep artifact actions escaped and command-addressable", () => {
  const renderers = createRenderers();
  const html = renderers.renderArtifactsView({
    artifacts: [{
      action: "Evidence <capture>",
      message: "Opened & verified",
      timestampMs: 1,
      activityId: "artifact-1",
      evidenceThreadId: "thread-1",
      connectorId: "connector-1",
    }],
  });

  assert.match(html, /Evidence &lt;capture&gt;/);
  assert.match(html, /Opened &amp; verified/);
  assert.match(html, /data-command="ioi\.chatSession\.openArtifact"/);
  assert.match(html, /data-command="ioi\.artifacts\.review"/);
  assert.match(html, /data-command="ioi\.artifacts\.openEvidence"/);
  assert.match(html, /data-command="ioi\.artifacts\.openPolicy"/);
  assert.match(html, /&quot;connectorId&quot;:&quot;connector-1&quot;/);
});

test("mode body renderers project policy metrics and empty state", () => {
  const renderers = createRenderers();

  assert.match(renderers.renderPolicyView({}), /Policy summary is not available/);

  const html = renderers.renderPolicyView({
    policy: {
      totalEntries: "2<",
      connectorCount: 3,
      connectedConnectorCount: 1,
      runtimeSkillCount: 4,
      authoritativeSourceCount: 5,
      activeIssueCount: "6&",
    },
  });
  assert.match(html, /Entries/);
  assert.match(html, /2&lt;/);
  assert.match(html, /6&amp;/);
  assert.match(html, /Approval and settlement authority remain outside/);
});

test("mode body renderers keep connector actions and direct mode projection stable", () => {
  const renderers = createRenderers();
  const connections = renderers.renderConnectionsView({
    connections: [{
      id: "connector-1",
      name: "Connector <one>",
      status: "ready",
      summary: "Dry-run & governed",
    }],
  });

  assert.match(connections, /Connector &lt;one&gt;/);
  assert.match(connections, /Dry-run &amp; governed/);
  assert.match(connections, /data-command="ioi\.connections\.openConnector"/);
  assert.match(connections, /data-command="ioi\.artifacts\.openPolicy"/);

  const direct = renderers.renderDirectModeActivityView({
    title: "Runs <mode>",
    command: "ioi.runs.refresh",
  });
  assert.match(direct, /data-testid="autopilot-direct-mode-activity"/);
  assert.match(direct, /Open Runs &lt;mode&gt;/);
  assert.match(direct, /data-command="ioi\.runs\.refresh"/);
});
