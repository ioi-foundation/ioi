import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createHypervisorShellHeader } = require("./shell-header.js");

function escapeHtml(value = "") {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function createHeader(options = {}) {
  return createHypervisorShellHeader({
    HYPERVISOR_MODE_BY_ID: {
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

test("Hypervisor shell header maps runtime tones", () => {
  const header = createHeader();

  assert.equal(header.shellStatusTone("connected"), "ready");
  assert.equal(header.shellStatusTone("queued"), "warn");
  assert.equal(header.shellStatusTone("policy denied"), "blocked");
  assert.equal(header.shellStatusTone("not_configured"), "muted");
});

test("Hypervisor shell header renders sanitized posture and commands", () => {
  const header = createHeader();
  const html = header.renderHypervisorShellHeader({
    workspace: { name: "Repo <One>", path: "/workspace/repo-one" },
    modelMounting: {
      instances: [{ status: "loaded" }],
      routes: [{ id: "route.local", displayName: "Local <Route>", status: "active" }],
      endpoints: [],
    },
    runs: [{ status: "running" }],
    summary: { policyIssueCount: 1 },
  }, "home");

  assert.match(html, /data-testid="hypervisor-workbench-shell-header"/);
  assert.match(html, /data-command="ioi\.commandCenter\.open"/);
  assert.match(html, /data-command="ioi\.code\.open"/);
  assert.match(html, /Repo &lt;One&gt;/);
  assert.match(html, /Local &lt;Route&gt;/);
  assert.match(html, /hypervisor-shell-chip is-ready/);
  assert.match(html, /hypervisor-shell-chip is-warn/);
});

test("Hypervisor shell header supports native-shell gating and code-mode action", () => {
  const nativeHeader = createHeader({ processEnv: { IOI_WORKBENCH_NATIVE_SHELL: "1" } });
  assert.equal(nativeHeader.renderHypervisorShellHeader({}, "home"), "");

  const codeHeader = createHeader();
  const html = codeHeader.renderHypervisorShellHeader({
    modelMounting: { instances: [], routes: [], endpoints: [] },
    runs: [],
    policy: {},
  }, "code");
  assert.match(html, /data-command="ioi\.hypervisor\.back"/);
  assert.match(html, /data-testid="back-to-hypervisor-from-code"/);
});

test("Hypervisor shell header styles expose the product shell selectors", () => {
  const header = createHeader();
  const styles = header.hypervisorShellHeaderStyles();

  assert.match(styles, /\.hypervisor-shell-header/);
  assert.match(styles, /\.hypervisor-shell-chip\.is-ready/);
});
