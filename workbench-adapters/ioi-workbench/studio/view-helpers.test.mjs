import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createStudioViewHelpers } = require("./view-helpers.js");

function escapeHtml(value = "") {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function createHelpers(now = () => 1_000_000) {
  return createStudioViewHelpers({ escapeHtml, now });
}

test("relative time keeps compact product labels", () => {
  const helpers = createHelpers(() => 3_600_000 + 17 * 60_000);

  assert.equal(helpers.formatRelativeTime(null), "now");
  assert.equal(helpers.formatRelativeTime(3_600_000 + 16 * 60_000 + 30_000), "<1m ago");
  assert.equal(helpers.formatRelativeTime(3_600_000), "17m ago");
  assert.equal(helpers.formatRelativeTime(60_000), "1h 16m ago");
});

test("command payload attrs and buttons escape command surfaces", () => {
  const helpers = createHelpers();

  assert.equal(helpers.commandPayloadAttr(null), "");
  assert.match(
    helpers.commandPayloadAttr({ scenarioId: "connector-fixture", label: "<test>" }),
    /data-payload=".*&lt;test&gt;.*"/,
  );

  const html = helpers.renderCommandButton({
    label: "Open <Studio>",
    command: "ioi.studio.open",
    payload: { source: "trace" },
  });
  assert.match(html, /class="action"/);
  assert.match(html, /data-command="ioi\.studio\.open"/);
  assert.match(html, /Open &lt;Studio&gt;/);
  assert.match(html, /&quot;source&quot;:&quot;trace&quot;/);
});

test("item stacks and empty state preserve shell structure", () => {
  const helpers = createHelpers();

  assert.match(helpers.renderItems([], "No <items>", () => ""), /No &lt;items&gt;/);
  assert.equal(
    helpers.renderItems([{ id: "one" }, { id: "two" }], "empty", (item) => `<span>${item.id}</span>`),
    `<div class="stack"><span>one</span><span>two</span></div>`,
  );
});

test("runtime summary and diagnostics escape projected state", () => {
  const helpers = createHelpers();
  const summary = helpers.renderRuntimeSummary({
    summary: {
      workflowCount: 1,
      runCount: 2,
      artifactCount: 3,
      connectorCount: 4,
      policyIssueCount: 5,
    },
  });
  assert.match(summary, /aria-label="IOI runtime snapshot"/);
  assert.match(summary, /runtime-strip__item/);
  assert.match(summary, /Policy issues/);
  assert.match(summary, /<strong>5<\/strong>/);

  assert.equal(helpers.renderDiagnostics({ diagnostics: [] }), "");
  const diagnostics = helpers.renderDiagnostics({
    diagnostics: [{ label: "bridge<one>", message: "failed & retried" }],
  });
  assert.match(diagnostics, /Bridge diagnostics/);
  assert.match(diagnostics, /bridge&lt;one&gt;/);
  assert.match(diagnostics, /failed &amp; retried/);
});
