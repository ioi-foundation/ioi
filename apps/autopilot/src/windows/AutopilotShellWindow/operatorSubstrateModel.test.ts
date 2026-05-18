import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  buildOperatorActivityRailModel,
  buildOperatorCommandCenterModel,
  type OperatorCommandCenterModel,
} from "./operatorSubstrateModel.ts";
import type { ProjectScope } from "./autopilotShellModel.ts";

const PROJECT: ProjectScope = {
  id: "autopilot-core",
  name: "Autopilot Core",
  description: "Worker control plane and operator shell.",
  environment: "Production",
  rootPath: ".",
};

test("operator command center is a daemon-runtime projection", () => {
  const model: OperatorCommandCenterModel = buildOperatorCommandCenterModel({
    activeView: "workspace",
    workflowSurface: "canvas",
    currentProject: PROJECT,
    notificationCount: 3,
    evidenceRefs: {
      receiptIds: ["receipt-1"],
    },
  });

  assert.equal(model.runtimeTruthSource, "daemon-runtime");
  assert.equal(model.scopeLabel, "Autopilot Core / Workspace");
  assert.equal(model.shortcutLabel, "Ctrl+K");
  assert.deepEqual(model.evidenceRefs.receiptIds, ["receipt-1"]);
  assert.ok(
    model.commands.some(
      (command) =>
        command.id === "runtime.receipts" &&
        command.source === "runtime-projection" &&
        command.route.kind === "primary-view" &&
        command.route.view === "runs",
    ),
  );
  assert.ok(
    model.commands.some(
      (command) =>
        command.id === "workspace.search" &&
        command.source === "workspace-projection" &&
        command.route.kind === "command-palette",
    ),
  );
});

test("operator activity rail is a shell projection with deterministic surfaces", () => {
  const model = buildOperatorActivityRailModel({
    activeView: "workflows",
    collapsed: true,
    notificationCount: 4,
  });

  assert.equal(model.runtimeTruthSource, "daemon-runtime");
  assert.equal(model.collapsed, true);
  assert.equal(model.chromeMode, "sidebar");
  assert.deepEqual(model.activeRoute, { kind: "primary-view", view: "workflows" });
  assert.deepEqual(
    model.items.map((item) => item.dataWindowSurface),
    [
      "search",
      "home",
      "chat",
      "inbox",
      "workspace",
      "workflows",
      "runs",
      "mounts",
      "capabilities",
      "policy",
      "settings",
      "profile",
    ],
  );
  assert.equal(
    model.items.find((item) => item.dataWindowSurface === "inbox")?.badgeCount,
    4,
  );
  assert.equal(
    model.items.find((item) => item.dataWindowSurface === "search")?.route.kind,
    "command-palette",
  );
});

test("operator substrate code does not introduce runtime ownership", () => {
  const source = readFileSync(
    "apps/autopilot/src/windows/AutopilotShellWindow/operatorSubstrateModel.ts",
    "utf8",
  );

  assert.match(source, /runtimeTruthSource: "daemon-runtime"/);
  assert.doesNotMatch(source, /new Runtime|createRuntime|React Flow shadow/i);
});

test("workspace embedding defers global command center to ChatIdeHeader", () => {
  const workspaceHost = readFileSync(
    "packages/workspace-substrate/src/components/WorkspaceHost.tsx",
    "utf8",
  );
  const workspaceShell = readFileSync(
    "apps/autopilot/src/surfaces/Workspace/WorkspaceShell.tsx",
    "utf8",
  );
  const chatHeader = readFileSync(
    "apps/autopilot/src/windows/AutopilotShellWindow/components/ChatIdeHeader.tsx",
    "utf8",
  );

  assert.match(workspaceHost, /hideGlobalCommandCenter\?: boolean/);
  assert.match(workspaceHost, /workspace-host--global-command-center-hidden/);
  assert.match(workspaceShell, /hideGlobalCommandCenter/);
  assert.match(chatHeader, /data-operator-command-center/);
});

test("workspace docked chat is real operator chrome, not screenshot hitboxes", () => {
  const workspaceHost = readFileSync(
    "packages/workspace-substrate/src/components/WorkspaceHost.tsx",
    "utf8",
  );

  assert.match(workspaceHost, /data-operator-chat-pane="docked"/);
  assert.match(workspaceHost, /data-inspection-target="workspace-chat-composer"/);
  assert.doesNotMatch(workspaceHost, /workspace-agent-dock-header-hitbox/);
  assert.doesNotMatch(workspaceHost, /workspace-agent-dock-hitbox/);
  assert.doesNotMatch(workspaceHost, /workbenchDockHeaderFullStrip/);
  assert.doesNotMatch(workspaceHost, /workbenchDockBodyStrip/);
});
