import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createAutopilotShellHeader } = require("./shell-header.js");

function escapeHtml(value = "") {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function createHeader(options = {}) {
  return createAutopilotShellHeader({
    AUTOPILOT_MODE_BY_ID: {
      home: { id: "home", title: "Home" },
      code: { id: "code", title: "Code" },
    },
    daemonEndpoint: () => options.daemonEndpoint ?? "http://127.0.0.1:0",
    escapeHtml,
    modelSnapshotFromState: (state) => state.modelMounting || { instances: [], routes: [], endpoints: [] },
    processEnv: options.processEnv || {},
    workspaceSummary: () => ({ name: "Fallback", path: "/workspace/fallback" }),
  });
}

test("Autopilot shell header maps runtime tones", () => {
  const header = createHeader();

  assert.equal(header.shellStatusTone("connected"), "ready");
  assert.equal(header.shellStatusTone("queued"), "warn");
  assert.equal(header.shellStatusTone("policy denied"), "blocked");
  assert.equal(header.shellStatusTone("not_configured"), "muted");
});

test("Autopilot shell header renders sanitized posture and commands", () => {
  const header = createHeader();
  const html = header.renderAutopilotShellHeader({
    workspace: { name: "Repo <One>", path: "/workspace/repo-one" },
    modelMounting: {
      instances: [{ status: "loaded" }],
      routes: [{ id: "route.local", displayName: "Local <Route>", status: "active" }],
      endpoints: [],
    },
    runs: [{ status: "running" }],
    summary: { policyIssueCount: 1 },
  }, "home");

  assert.match(html, /data-testid="autopilot-workbench-shell-header"/);
  assert.match(html, /data-command="ioi\.commandCenter\.open"/);
  assert.match(html, /data-command="ioi\.code\.open"/);
  assert.match(html, /Repo &lt;One&gt;/);
  assert.match(html, /Local &lt;Route&gt;/);
  assert.match(html, /autopilot-shell-chip is-ready/);
  assert.match(html, /autopilot-shell-chip is-warn/);
});

test("Autopilot shell header supports native-shell gating and code-mode action", () => {
  const nativeHeader = createHeader({ processEnv: { IOI_WORKBENCH_NATIVE_SHELL: "1" } });
  assert.equal(nativeHeader.renderAutopilotShellHeader({}, "home"), "");

  const codeHeader = createHeader();
  const html = codeHeader.renderAutopilotShellHeader({
    modelMounting: { instances: [], routes: [], endpoints: [] },
    runs: [],
    policy: {},
  }, "code");
  assert.match(html, /data-command="ioi\.autopilot\.back"/);
  assert.match(html, /data-testid="back-to-autopilot-from-code"/);
});

test("Autopilot shell header styles expose the product shell selectors", () => {
  const header = createHeader();
  const styles = header.autopilotShellHeaderStyles();

  assert.match(styles, /\.autopilot-shell-header/);
  assert.match(styles, /\.autopilot-shell-chip\.is-ready/);
});
