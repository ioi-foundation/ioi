import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
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
