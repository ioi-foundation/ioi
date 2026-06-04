import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createStudioOverviewView } = require("./overview-view.js");

function escapeHtml(value = "") {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function createView() {
  return createStudioOverviewView({
    commandPayloadAttr: (payload) => payload === undefined
      ? ""
      : ` data-payload="${escapeHtml(JSON.stringify(payload))}"`,
    escapeHtml,
  });
}

test("overview tone maps runtime states to product status classes", () => {
  const view = createView();

  assert.equal(view.overviewTone("connected"), "ready");
  assert.equal(view.overviewTone("loaded model"), "ready");
  assert.equal(view.overviewTone("degraded endpoint"), "warn");
  assert.equal(view.overviewTone("pending"), "warn");
  assert.equal(view.overviewTone("policy denied"), "blocked");
  assert.equal(view.overviewTone("not_configured"), "muted");
});

test("overview pill and rows escape product text and tone classes", () => {
  const view = createView();

  const pill = view.overviewPill("Daemon <status>", "ready & loaded");
  assert.match(pill, /overview-pill is-ready/);
  assert.match(pill, /Daemon &lt;status&gt;/);
  assert.match(pill, /ready &amp; loaded/);

  const row = view.renderOverviewRow("Models", "1 <model>", "loaded & verified", "ready");
  assert.match(row, /overview-row__label/);
  assert.match(row, /1 &lt;model&gt;/);
  assert.match(row, /loaded &amp; verified/);
});

test("overview actions preserve command payload affordances", () => {
  const view = createView();
  const html = view.renderOverviewAction({
    label: "Connector <Dry Run>",
    description: "Exercise & verify",
    command: "ioi.workflow.openComposer",
    payload: { scenarioId: "connector-fixture", phase: "connector-fixture" },
    tone: "primary",
  });

  assert.match(html, /class="overview-action is-primary"/);
  assert.match(html, /data-command="ioi\.workflow\.openComposer"/);
  assert.match(html, /Connector &lt;Dry Run&gt;/);
  assert.match(html, /Exercise &amp; verify/);
  assert.match(html, /&quot;scenarioId&quot;:&quot;connector-fixture&quot;/);
});
