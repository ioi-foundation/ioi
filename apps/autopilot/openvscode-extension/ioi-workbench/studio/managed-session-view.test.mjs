import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { test } from "node:test";

const require = createRequire(import.meta.url);
const { createStudioManagedSessionView } = require("./managed-session-view.js");

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function createView() {
  return createStudioManagedSessionView({
    escapeHtml,
    firstArray: (value) => Array.isArray(value) ? value : [],
  });
}

test("managed session view attaches bounded session cards to work records", () => {
  const view = createView();
  assert.equal(view.studioWorkRecordWithSessionCards(null, []), null);

  const workRecord = view.studioWorkRecordWithSessionCards(
    { status: "running", lines: ["Existing line"], stepCount: 1 },
    [
      { id: "one" },
      { id: "two" },
      { id: "three" },
      { id: "four" },
    ],
  );

  assert.equal(workRecord.status, "running");
  assert.deepEqual(workRecord.lines, ["Existing line", "Managed 4 browser/computer live sessions"]);
  assert.deepEqual(workRecord.sessionCards.map((card) => card.id), ["two", "three", "four"]);
  assert.equal(workRecord.stepCount, 2);

  const existingLine = view.studioWorkRecordWithSessionCards(
    { lines: ["Managed 1 browser/computer live session"] },
    [{ id: "one" }],
  );
  assert.deepEqual(existingLine.lines, ["Managed 1 browser/computer live session"]);
});

test("managed session view renders waiting handoff and stable control test ids", () => {
  const view = createView();
  const rows = view.studioManagedSessionRows([{
    id: "session-1",
    kind: "local_browser",
    surfaceLabel: "Local browser",
    status: "waiting_for_user",
    statusLabel: "Waiting for user",
    lastTool: "browser__open",
    controlState: "take_over",
    waitingForUser: true,
    pageTitle: "Manual auth <handoff>",
    url: "https://example.test/login",
    detail: "Operator completes manual authentication.",
  }]);

  assert.match(rows, /data-testid="studio-managed-sessions"/);
  assert.match(rows, /data-session-id="session-1"/);
  assert.match(rows, /data-session-kind="local_browser"/);
  assert.match(rows, /data-control-state="take_over"/);
  assert.match(rows, /studio-status-dot--blocked/);
  assert.match(rows, /data-testid="studio-managed-session-waiting"/);
  assert.match(rows, /Manual auth &lt;handoff&gt;/);
  assert.match(rows, /data-studio-managed-session-control="observe"/);
  assert.match(rows, /data-studio-managed-session-control="take_over" aria-pressed="true"/);
  assert.match(rows, /data-studio-managed-session-control="return_agent"/);
});

test("managed session view renders empty and default sandbox session states", () => {
  const view = createView();
  assert.equal(view.studioManagedSessionRows([]), "");

  const rows = view.studioManagedSessionRows([{ id: "session-2" }]);
  assert.match(rows, /data-session-kind="sandbox_browser"/);
  assert.match(rows, /data-session-label="Sandbox browser"/);
  assert.match(rows, /data-session-status="complete"/);
  assert.match(rows, /data-control-state="observe"/);
  assert.match(rows, /studio-status-dot--completed/);
  assert.match(rows, /Runtime-managed viewport/);
});
