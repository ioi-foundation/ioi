import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const gateSource = readFileSync(
  new URL("./WorkspaceRepositoryGate.tsx", import.meta.url),
  "utf8",
);
const shellCss = readFileSync(
  new URL(
    "../../windows/HypervisorShellWindow/styles/hypervisor-shell/shell-base.css",
    import.meta.url,
  ),
  "utf8",
);

test("Workbench landing is a product-facing adapter hub", () => {
  assert.match(gateSource, /data-workbench-adapter-hub="true"/);
  assert.match(gateSource, /<h1>Workbench<\/h1>/);
  assert.match(gateSource, /Adapter targets/);
  assert.match(gateSource, /Choose where Workbench opens/);
  assert.match(gateSource, /embedded editor, a desktop editor/);
  assert.match(gateSource, /browser-based code editor/);
  assert.match(gateSource, /HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES/);
  assert.match(gateSource, /getWorkbenchAdapterPreferenceRef/);
  assert.match(gateSource, /buildWorkbenchAdapterLaunchPlan/);
  assert.match(gateSource, /data-workbench-adapter-preference/);
  assert.match(gateSource, /data-workbench-adapter-executor-lane/);
  assert.match(gateSource, /data-workbench-adapter-control-action/);
  assert.match(gateSource, /data-workbench-adapter-control-channel-ref/);
  assert.match(gateSource, /adapterControlActionLabel/);
  assert.match(gateSource, /workspace-repository-gate__adapter-list/);
  assert.match(gateSource, /workspace-repository-gate__adapter-row/);
  assert.match(gateSource, /workspace-repository-gate__adapter-control/);
  assert.match(gateSource, /adapterAccessLabel/);
  assert.match(gateSource, /aria-pressed=\{selected\}/);
  assert.match(gateSource, /persistWorkbenchAdapterPreferenceRef/);
  assert.match(gateSource, /What's new\?/);
  assert.match(gateSource, /embedded, desktop, and browser-based/);
  assert.doesNotMatch(gateSource, /WORKBENCH_ADAPTER_TARGETS/);
  assert.doesNotMatch(
    gateSource,
    /daemon gates|Agentgres|wallet\.network|Hypervisor Core|runtime truth|governed adapter target|Governance|Adapter policy|Review policy/,
  );
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
    /\.workspace-repository-gate__adapter-list\s*\{/,
  );
  assert.match(shellCss, /\.workspace-repository-gate__adapter-row\s*\{/);
});
