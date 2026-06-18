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

test("Workspace shell opens on the adapter hub before a workspace target", () => {
  assert.match(
    shellSource,
    /useState<WorkspaceShellMode>\("repository-gate"\)/,
    "The Workbench surface must first present workspace and adapter targets.",
  );
  assert.match(
    shellSource,
    /const workbenchProject = selectedRepository \?\? currentProject;/,
    "The current project must remain a valid workbench target after adapter selection.",
  );
  assert.match(
    shellSource,
    /const workbenchActive = active && shellMode === "workbench";/,
    "Workbench runtime startup must wait until an explicit target open.",
  );
  assert.match(
    shellSource,
    /setShellMode\("workbench"\);/,
    "Opening a repository or target must still enter the Workbench session.",
  );
});

test("Repository chooser remains the adapter-hub entry and return path", () => {
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
