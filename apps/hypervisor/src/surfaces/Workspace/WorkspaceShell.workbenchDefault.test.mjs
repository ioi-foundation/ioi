import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const shellSource = readFileSync(
  new URL("./WorkspaceShell.tsx", import.meta.url),
  "utf8",
);
const shellCss = readFileSync(
  new URL(
    "../../windows/HypervisorShellWindow/styles/hypervisor-shell/shell-base.css",
    import.meta.url,
  ),
  "utf8",
);
const traceCss = readFileSync(
  new URL(
    "../../windows/HypervisorShellWindow/styles/hypervisor-shell/trace-and-welcome.css",
    import.meta.url,
  ),
  "utf8",
);

test("Workspace shell opens directly into the governed workbench", () => {
  assert.match(
    shellSource,
    /useState<WorkspaceShellMode>\("workbench"\)/,
    "Workbench must be the first impression for the workspace route.",
  );
  assert.match(
    shellSource,
    /const workbenchProject = selectedRepository \?\? currentProject;/,
    "The current project must be a valid workbench target without repository gate selection.",
  );
  assert.match(
    shellSource,
    /const workbenchActive = active && shellMode === "workbench";/,
    "Workbench startup must not be blocked on selecting a repository first.",
  );
});

test("Repository chooser remains an explicit secondary action", () => {
  assert.match(shellSource, /const returnToRepositoryGate = \(\) => \{/);
  assert.match(shellSource, /setShellMode\("repository-gate"\);/);
  assert.match(shellSource, /<WorkspaceRepositoryGate/);
});

test("Workbench degraded state keeps the light IOI session posture", () => {
  assert.match(shellSource, /chat-workspace-oss-shell__fallback-grid/);
  assert.match(shellSource, /chat-workspace-oss-shell__environment/);
  assert.match(shellSource, /chat-workspace-oss-shell__changes/);
  assert.match(shellSource, />Ports & Services</);
  assert.match(
    shellSource,
    /\{!overlayVisible \? \([\s\S]*?chat-workspace-oss-shell__workbench-header/,
    "The fallback owns the route chrome and must not render an extra Workbench header.",
  );
  assert.match(
    shellCss,
    /\.chat-workspace-oss-shell\s*\{[\s\S]*?background: #f7f7f6;/,
  );
  assert.match(
    shellCss,
    /\.chat-workspace-oss-shell__workbench-header\s*\{[\s\S]*?background: #ffffff;/,
  );
  assert.match(
    traceCss,
    /\.chat-workspace-oss-shell__overlay\s*\{[\s\S]*?background:[\s\S]*?#f7f7f6;/,
  );
  assert.match(
    traceCss,
    /\.chat-workspace-oss-shell__fallback-grid\s*\{[\s\S]*?grid-template-columns: minmax\(0, 1fr\) 388px;/,
  );
  assert.match(
    traceCss,
    /\.chat-workspace-oss-shell__environment\s*\{[\s\S]*?background: #ffffff;/,
  );
  assert.match(
    traceCss,
    /\.chat-workspace-oss-shell__changes\s*\{[\s\S]*?border-left: 1px solid #dedede;/,
  );
});
