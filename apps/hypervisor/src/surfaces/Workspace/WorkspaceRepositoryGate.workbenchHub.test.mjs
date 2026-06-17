import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const gateSource = readFileSync(
  new URL("./WorkspaceRepositoryGate.tsx", import.meta.url),
  "utf8",
);
const shellCss = readFileSync(
  new URL(
    "../../windows/HypervisorShellWindow/styles/autopilot-shell/shell-base.css",
    import.meta.url,
  ),
  "utf8",
);

test("Workbench landing is an adapter hub over Hypervisor Core", () => {
  assert.match(gateSource, /data-workbench-adapter-hub="true"/);
  assert.match(gateSource, /<h1>Workbench<\/h1>/);
  assert.match(gateSource, /Adapter targets/);
  assert.match(gateSource, /Choose a governed adapter target/);
  assert.match(gateSource, /editors, terminals, browsers, VMs, and/);
  assert.match(gateSource, /adapter targets over Hypervisor Core/);
  assert.match(gateSource, /not the parent product or runtime truth/);
  assert.match(gateSource, /WORKBENCH_ADAPTER_TARGETS/);
  assert.match(gateSource, /VS Code \/ OpenVSCode/);
  assert.match(gateSource, /Cursor \/ Windsurf/);
  assert.match(gateSource, /JetBrains \/ Terminal/);
  assert.match(gateSource, /Browser \/ VM \/ Node/);
});

test("Workbench landing no longer opens as a code repository PR console", () => {
  assert.doesNotMatch(gateSource, /<h1>Code repositories<\/h1>/);
  assert.doesNotMatch(gateSource, />Pull requests</);
  assert.doesNotMatch(gateSource, /No pull requests created by you/);
  assert.doesNotMatch(gateSource, /Find pull requests/);
  assert.doesNotMatch(gateSource, /Search repositories/);
});

test("Workbench adapter hub has a stable layout hook", () => {
  assert.match(shellCss, /\.workspace-repository-gate__adapter-hub\s*\{/);
  assert.match(
    shellCss,
    /\.workspace-repository-gate__adapter-hub \.workspace-repository-gate__category-grid/,
  );
});
