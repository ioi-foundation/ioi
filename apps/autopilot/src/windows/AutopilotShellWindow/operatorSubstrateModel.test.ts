import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  buildOperatorActivityRailModel,
  buildOperatorCommandCenterModel,
  buildWorkspaceSubstrateTargetIndex,
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
  assert.deepEqual(model.activeRoute, {
    kind: "primary-view",
    view: "workflows",
  });
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
  assert.match(source, /interface OperatorChatComposerModel/);
  assert.match(source, /interface OperatorChatContextControlModel/);
  assert.match(source, /interface OperatorChatPaneChrome/);
  assert.doesNotMatch(source, /new Runtime|createRuntime|React Flow shadow/i);
});

test("workspace substrate target index exposes controlled UI before coordinate fallback", () => {
  const index = buildWorkspaceSubstrateTargetIndex({
    generatedAtMs: 1_763_000_001_000,
    directWebview: {
      surfaceId: "surface:workspace",
      label: "OpenVSCode",
      bounds: { x: 10, y: 20, width: 900, height: 700 },
      screenBounds: { x: 100, y: 200, width: 900, height: 700 },
    },
  });

  assert.equal(index.schemaVersion, "ioi.workspace-substrate-target-index.v1");
  assert.equal(index.targets[0]?.runtimeTruthSource, "daemon-runtime");
  assert.ok(
    index.targets.some(
      (target) => target.targetId === "operator.command-center",
    ),
  );
  assert.ok(
    index.targets.some((target) => target.targetId === "workspace.editor"),
  );
  assert.ok(
    index.targets.some((target) => target.targetId === "workflow.node"),
  );
  assert.ok(
    index.targets.some(
      (target) =>
        target.targetId === "direct-webview.surface:workspace" &&
        target.locators.some((locator) => locator.kind === "direct-webview"),
    ),
  );
  assert.ok(
    index.targets
      .flatMap((target) => target.locators)
      .some(
        (locator) =>
          locator.kind === "data-attribute" &&
          locator.selector === '[data-inspection-target="workspace-editor"]',
      ),
  );
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

test("direct OpenVSCode workspace failures stay in integrated surface chrome", () => {
  const workspaceShell = readFileSync(
    "apps/autopilot/src/surfaces/Workspace/WorkspaceShell.tsx",
    "utf8",
  );
  const workspaceStyles = readFileSync(
    "apps/autopilot/src/windows/AutopilotShellWindow/styles/autopilot-shell/trace-and-welcome.css",
    "utf8",
  );

  assert.match(workspaceShell, /directOpenVsCodeSurfaceVisible/);
  assert.match(workspaceShell, /surfaceRuntimeNotice/);
  assert.match(workspaceShell, /!overlayVisible && surfaceNotice/);
  assert.match(workspaceShell, /chat-workspace-oss-shell__surface-notice/);
  assert.match(workspaceShell, /chat-workspace-oss-shell__diagnostics/);
  assert.doesNotMatch(
    workspaceShell,
    /const effectiveError = error \?\? surfaceRuntimeError/,
  );
  assert.doesNotMatch(workspaceShell, /Force reveal now/);
  assert.match(workspaceStyles, /chat-workspace-oss-shell__surface-notice/);
});

test("workspace docked chat is real operator chrome, not screenshot hitboxes", () => {
  const workspaceHost = readFileSync(
    "packages/workspace-substrate/src/components/WorkspaceHost.tsx",
    "utf8",
  );
  const operatorChatPane = readFileSync(
    "packages/workspace-substrate/src/components/OperatorChatPane.tsx",
    "utf8",
  );
  const chatConversationSurface = readFileSync(
    "apps/autopilot/src/windows/ChatShellWindow/components/ChatConversationSurface.tsx",
    "utf8",
  );
  const chatInputSection = readFileSync(
    "apps/autopilot/src/windows/ChatShellWindow/components/ChatInputSection.tsx",
    "utf8",
  );

  assert.match(workspaceHost, /<OperatorChatPane/);
  assert.match(workspaceHost, /dataOperatorChatPane="docked"/);
  assert.match(workspaceHost, /dataInspectionTarget="workspace-chat-pane"/);
  assert.match(operatorChatPane, /data-operator-chat-pane=/);
  assert.match(
    operatorChatPane,
    /data-inspection-target=\{dataInspectionTarget/,
  );
  assert.match(
    operatorChatPane,
    /data-inspection-target="workspace-chat-composer"/,
  );
  assert.match(chatConversationSurface, /<OperatorChatPane/);
  assert.match(
    chatConversationSurface,
    /dataInspectionTarget="operator-chat-pane"/,
  );
  assert.match(
    chatInputSection,
    /data-inspection-target="operator-chat-composer"/,
  );
  assert.doesNotMatch(chatConversationSurface, /spot-workbench-chat-topbar/);
  assert.doesNotMatch(workspaceHost, /function WorkbenchAgentDock/);
  assert.doesNotMatch(workspaceHost, /workspace-agent-dock-header-hitbox/);
  assert.doesNotMatch(workspaceHost, /workspace-agent-dock-hitbox/);
  assert.doesNotMatch(workspaceHost, /workbenchDockHeaderFullStrip/);
  assert.doesNotMatch(workspaceHost, /workbenchDockBodyStrip/);
});

test("embedded OpenVSCode defers global search to Autopilot chrome", () => {
  const workspaceIde = readFileSync(
    "apps/autopilot/src-tauri/src/workspace_ide.rs",
    "utf8",
  );
  const homeView = readFileSync(
    "apps/autopilot/src/surfaces/Home/HomeView.tsx",
    "utf8",
  );
  const homeOnboardingModel = readFileSync(
    "apps/autopilot/src/surfaces/Home/homeOnboardingModel.ts",
    "utf8",
  );
  const bundledExtension = readFileSync(
    "apps/autopilot/openvscode-extension/ioi-workbench/extension.js",
    "utf8",
  );

  assert.match(
    workspaceIde,
    /"window\.commandCenter"\.to_string\(\),\s*Value::Bool\(false\)/,
  );
  assert.match(
    workspaceIde,
    /fn ensure_openvscode_user_keybindings[\s\S]*"-workbench\.action\.quickOpen"[\s\S]*"-workbench\.action\.showCommands"/,
  );
  assert.match(
    workspaceIde,
    /fn openvscode_user_config_owned[\s\S]*"window\.commandCenter"[\s\S]*workbench\.action\.quickOpen/,
  );
  assert.match(
    workspaceIde,
    /openvscode_user_config_owned\(&existing_user_data_dir\)[\s\S]*return Ok\(current_session_info\(existing\)\)[\s\S]*kill_session\(existing\)/,
  );
  assert.match(
    homeView,
    /case "quickOpen\.open":[\s\S]*onOpenCommandPalette\(\);[\s\S]*return;/,
  );
  assert.doesNotMatch(
    homeView,
    /case "quickOpen\.open":[\s\S]*queueWorkbenchCommand\("workbench\.action\.quickOpen"\)/,
  );
  assert.match(homeOnboardingModel, /targetRoute: "Autopilot command center"/);
  assert.doesNotMatch(
    homeOnboardingModel,
    /toSide:workbench\.action\.quickOpen/,
  );
  assert.doesNotMatch(
    bundledExtension,
    /label: "Open command palette"[\s\S]*command: "workbench\.action\.showCommands"/,
  );
});

test("controlled substrate surfaces expose inspection target attributes", () => {
  const chatHeader = readFileSync(
    "apps/autopilot/src/windows/AutopilotShellWindow/components/ChatIdeHeader.tsx",
    "utf8",
  );
  const activityRail = readFileSync(
    "apps/autopilot/src/windows/AutopilotShellWindow/components/ChatLocalActivityBar.tsx",
    "utf8",
  );
  const directSurface = readFileSync(
    "apps/autopilot/src/surfaces/Workspace/OpenVsCodeDirectSurface.tsx",
    "utf8",
  );
  const workspaceRail = readFileSync(
    "packages/workspace-substrate/src/components/WorkspaceRail.tsx",
    "utf8",
  );
  const explorer = readFileSync(
    "packages/workspace-substrate/src/components/WorkspaceExplorerPane.tsx",
    "utf8",
  );
  const editor = readFileSync(
    "packages/workspace-substrate/src/components/WorkspaceEditorPane.tsx",
    "utf8",
  );
  const composer = readFileSync(
    "packages/agent-ide/src/WorkflowComposer/view.tsx",
    "utf8",
  );
  const canvasNode = readFileSync(
    "packages/agent-ide/src/features/Editor/Canvas/Nodes/CanvasNode.tsx",
    "utf8",
  );

  assert.match(chatHeader, /data-inspection-target="operator-command-center"/);
  assert.match(activityRail, /data-inspection-target="operator-activity-rail"/);
  assert.match(directSurface, /__AUTOPILOT_GET_WORKBENCH_TARGET_INDEX__/);
  assert.match(
    directSurface,
    /data-inspection-target="direct-openvscode-webview"/,
  );
  assert.match(workspaceRail, /data-inspection-target="workspace-rail"/);
  assert.match(explorer, /data-inspection-target="workspace-explorer-row"/);
  assert.match(editor, /data-inspection-target="workspace-editor-stage"/);
  assert.match(composer, /data-inspection-target="workflow-composer"/);
  assert.match(canvasNode, /data-inspection-target="workflow-node"/);
});

test("browser-inspected surfaces guard desktop-only event listeners", () => {
  const capabilitiesController = readFileSync(
    "apps/autopilot/src/surfaces/Capabilities/components/useCapabilitiesController.ts",
    "utf8",
  );

  assert.match(capabilitiesController, /listenIfTauri/);
  assert.doesNotMatch(capabilitiesController, /from "@tauri-apps\/api\/event"/);
});
