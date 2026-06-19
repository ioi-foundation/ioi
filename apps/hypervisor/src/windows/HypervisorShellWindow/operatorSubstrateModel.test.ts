import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

import {
  buildOperatorActivityRailModel,
  buildWorkspaceSubstrateTargetIndex,
} from "./operatorSubstrateModel.ts";

const RETIRED_NATIVE_APP_PATH = ["apps/hypervisor", "src-tauri"].join("/");
const RETIRED_NATIVE_ARCHIVE_PATH = [
  "internal-docs/legacy",
  "autopilot-tauri-src",
].join("/");

test("retired native app path and archive stay absent", () => {
  assert.equal(existsSync(RETIRED_NATIVE_APP_PATH), false);
  assert.equal(existsSync(RETIRED_NATIVE_ARCHIVE_PATH), false);
});

test("operator activity rail is a shell projection with deterministic surfaces", () => {
  const model = buildOperatorActivityRailModel({
    activeView: "automations",
    collapsed: true,
    notificationCount: 4,
  });

  assert.equal(model.runtimeTruthSource, "daemon-runtime");
  assert.equal(model.collapsed, true);
  assert.equal(model.chromeMode, "sidebar");
  assert.deepEqual(model.activeRoute, {
    kind: "primary-view",
    view: "automations",
  });
  assert.deepEqual(
    model.items.map((item) => item.dataWindowSurface),
    [
      "search",
      "home",
      "sessions",
      "projects",
      "missions",
      "workbench",
      "automations",
      "insights",
      "agents",
      "models",
      "privacy",
      "providers",
      "environments",
      "foundry",
      "authority",
      "receipts",
      "settings",
      "profile",
    ],
  );
  assert.equal(
    model.items.find((item) => item.dataWindowSurface === "missions")
      ?.badgeCount,
    4,
  );
  assert.equal(
    model.items.find((item) => item.dataWindowSurface === "workbench")
      ?.routeState,
    "active_route",
  );
  assert.equal(
    model.items.find((item) => item.dataWindowSurface === "providers")
      ?.routeState,
    "active_route",
  );
  assert.equal(
    model.items.find((item) => item.dataWindowSurface === "environments")
      ?.group,
    "governance",
  );
  assert.equal(
    model.items.find((item) => item.dataWindowSurface === "search")?.route.kind,
    "command-palette",
  );
});

test("operator substrate code does not introduce runtime ownership", () => {
  const source = readFileSync(
    "apps/hypervisor/src/windows/HypervisorShellWindow/operatorSubstrateModel.ts",
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
  });

  assert.equal(index.schemaVersion, "ioi.workspace-substrate-target-index.v1");
  assert.equal(index.targets[0]?.runtimeTruthSource, "daemon-runtime");
  assert.ok(
    index.targets.every(
      (target) => target.targetId !== "operator.command-center",
    ),
  );
  assert.ok(
    index.targets.some((target) => target.targetId === "workspace.editor"),
  );
  assert.ok(
    index.targets.some((target) => target.targetId === "workflow.node"),
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

test("operator composer chrome stays in workspace substrate without alternate chat shell", () => {
  const operatorChatPane = readFileSync(
    "packages/workspace-substrate/src/components/OperatorChatPane.tsx",
    "utf8",
  );
  const commandMenus = readFileSync(
    "apps/hypervisor/src/components/ui/CommandMenus.css",
    "utf8",
  );
  const commandPalette = readFileSync(
    "apps/hypervisor/src/components/CommandPalette.tsx",
    "utf8",
  );
  const codicon = readFileSync(
    "packages/workspace-substrate/src/components/Codicon.tsx",
    "utf8",
  );

  assert.match(operatorChatPane, /data-operator-chat-pane=/);
  assert.match(
    operatorChatPane,
    /data-inspection-target=\{dataInspectionTarget/,
  );
  assert.match(
    operatorChatPane,
    /data-inspection-target="workspace-chat-composer"/,
  );
  assert.equal(
    existsSync("apps/hypervisor/src/windows/ChatShellWindow"),
    false,
    "the app should not retain the retired alternate ChatShellWindow UI tree",
  );
  assert.match(operatorChatPane, /operator-chat-pane__empty-main/);
  assert.match(operatorChatPane, /operator-chat-pane__suggestions/);
  assert.match(
    commandPalette,
    /QUICK_SWITCHER_ANCHOR_SELECTOR =\s*'\[data-hypervisor-quick-switcher-anchor="true"\]'/,
  );
  assert.match(
    commandMenus,
    /\.spot-slash-menu--palette \.spot-slash-menu-search/,
  );
  assert.match(commandMenus, /\.spot-quick-switcher-menu-overlay/);
  assert.match(commandMenus, /\.spot-slash-menu--quick-switcher/);
  assert.match(commandMenus, /position: fixed/);
  assert.match(commandMenus, /border-radius: 6px/);
  assert.match(commandMenus, /background: #242424/);
  assert.match(commandMenus, /background: #075486/);
  assert.match(codicon, /codicon-\$\{name\}/);
  assert.match(codicon, /"auxiliarybar-maximize": "screen-full"/);
});

test("workspace adapter commands defer global search to Hypervisor chrome", () => {
  const homeView = readFileSync(
    "apps/hypervisor/src/surfaces/Home/HomeView.tsx",
    "utf8",
  );
  const bundledExtension = readFileSync(
    "code-editor-adapters/ioi-code-editor-adapter/extension.js",
    "utf8",
  );

  assert.doesNotMatch(
    homeView,
    /case "quickOpen\.open":[\s\S]*queueWorkbenchCommand\("workbench\.action\.quickOpen"\)/,
  );
  assert.doesNotMatch(homeView, /toSide:workbench\.action\.quickOpen/);
  assert.doesNotMatch(
    bundledExtension,
    /label: "Open command palette"[\s\S]*command: "workbench\.action\.showCommands"/,
  );
  assert.match(bundledExtension, /startCodeEditorContextPublisher/);
});

test("Hypervisor command palette anchors to the left-rail quick switcher", () => {
  const commandPalette = readFileSync(
    "apps/hypervisor/src/components/CommandPalette.tsx",
    "utf8",
  );
  const commandPaletteStyles = readFileSync(
    "apps/hypervisor/src/components/CommandPalette.css",
    "utf8",
  );
  const overlayBlock =
    commandPaletteStyles.match(/\.command-palette-overlay\s*\{[^}]*\}/)?.[0] ??
    "";

  assert.match(
    commandPalette,
    /QUICK_SWITCHER_ANCHOR_SELECTOR =\s*'\[data-hypervisor-quick-switcher-anchor="true"\]'/,
  );
  assert.match(commandPalette, /getBoundingClientRect\(\)/);
  assert.match(commandPalette, /initialQuery = ""/);
  assert.match(commandPalette, /mode = "default"/);
  assert.match(
    commandPalette,
    /CommandPaletteDisplayMode = "default" \| "tools"/,
  );
  assert.match(commandPalette, /useState\(initialQuery\)/);
  assert.match(commandPalette, /style=\{palettePosition\}/);
  assert.match(commandPalette, /mode === "tools"[\s\S]*"Select a tool"/);
  assert.match(commandPalette, /title: "Auto context enabled"/);
  assert.match(commandPalette, /title: "Workspace context"/);
  assert.match(commandPalette, /title: "Manage tools"/);
  assert.match(commandPalette, /id: "built-in-tools", title: "Built-In"/);
  assert.match(commandPalette, /id: "live-tools", title: "Live Tools"/);
  assert.match(
    commandPalette,
    /window\.addEventListener\("resize", computePosition\)/,
  );
  assert.match(
    commandPalette,
    /window\.addEventListener\("scroll", computePosition, true\)/,
  );
  assert.match(
    commandPaletteStyles,
    /\.command-palette-overlay\s*\{[\s\S]*background: transparent;/,
  );
  assert.match(
    commandPaletteStyles,
    /\.command-palette-shell\s*\{[\s\S]*position: fixed;/,
  );
  assert.doesNotMatch(overlayBlock, /display: flex/);
  assert.doesNotMatch(overlayBlock, /justify-content: center/);
  assert.doesNotMatch(
    commandPaletteStyles,
    /padding: clamp\(28px, 7vh, 72px\)/,
  );
});

test("controlled substrate surfaces expose inspection target attributes", () => {
  const chatHeader = readFileSync(
    "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorClientHeader.tsx",
    "utf8",
  );
  const activityRail = readFileSync(
    "apps/hypervisor/src/windows/HypervisorShellWindow/components/HypervisorActivityRail.tsx",
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
    "packages/hypervisor-workbench/src/WorkflowComposer/view.tsx",
    "utf8",
  );
  const canvasNode = readFileSync(
    "packages/hypervisor-workbench/src/features/Editor/Canvas/Nodes/CanvasNode.tsx",
    "utf8",
  );

  assert.doesNotMatch(chatHeader, /data-inspection-target="operator-command-center"/);
  assert.doesNotMatch(chatHeader, /data-operator-command-center/);
  assert.match(activityRail, /data-hypervisor-quick-switcher-anchor=/);
  assert.match(activityRail, /data-inspection-target="operator-activity-rail"/);
  assert.match(workspaceRail, /data-inspection-target="workspace-rail"/);
  assert.match(explorer, /data-inspection-target="workspace-explorer-row"/);
  assert.match(editor, /data-inspection-target="workspace-editor-stage"/);
  assert.match(composer, /data-inspection-target="workflow-composer"/);
  assert.match(canvasNode, /data-inspection-target="workflow-node"/);
});

test("browser-inspected surfaces guard desktop-only event listeners", () => {
  const capabilitiesController = readFileSync(
    "apps/hypervisor/src/surfaces/Capabilities/components/useCapabilitiesController.ts",
    "utf8",
  );

  assert.match(capabilitiesController, /listenIfHostBridge/);
  assert.doesNotMatch(capabilitiesController, /from "@[^"]*tauri[^"]*"/i);
});
