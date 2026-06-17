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
    /\.chat-workspace-oss-shell__overlay-card\s*\{[\s\S]*?background: #ffffff;/,
  );
});
