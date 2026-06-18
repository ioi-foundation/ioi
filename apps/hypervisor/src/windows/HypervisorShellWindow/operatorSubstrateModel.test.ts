import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import test from "node:test";

import {
  buildOperatorActivityRailModel,
  buildOperatorCommandCenterModel,
  buildWorkspaceSubstrateTargetIndex,
  type OperatorCommandCenterModel,
} from "./operatorSubstrateModel.ts";
import type { ProjectScope } from "./hypervisorShellModel.ts";

const PROJECT: ProjectScope = {
  id: "hypervisor-core",
  name: "Hypervisor Core",
  description:
    "Shared substrate for governed sessions, adapters, and operator surfaces.",
  environment: "Production",
  rootPath: ".",
};

const RETIRED_NATIVE_APP_PATH = ["apps/hypervisor", "src-tauri"].join("/");
const RETIRED_NATIVE_ARCHIVE_PATH = [
  "internal-docs/legacy",
  "autopilot-tauri-src",
].join("/");

test("retired native app path and archive stay absent", () => {
  assert.equal(existsSync(RETIRED_NATIVE_APP_PATH), false);
  assert.equal(existsSync(RETIRED_NATIVE_ARCHIVE_PATH), false);
});

test("operator command center is a daemon-runtime projection", () => {
  const model: OperatorCommandCenterModel = buildOperatorCommandCenterModel({
    activeView: "workbench",
    currentProject: PROJECT,
    notificationCount: 3,
    evidenceRefs: {
      receiptIds: ["receipt-1"],
    },
  });

  assert.equal(model.runtimeTruthSource, "daemon-runtime");
  assert.equal(model.scopeLabel, "Hypervisor Core / Workbench");
  assert.equal(model.shortcutLabel, "Ctrl+K");
  assert.deepEqual(model.evidenceRefs.receiptIds, ["receipt-1"]);
  assert.ok(
    model.commands.some(
      (command) =>
        command.id === "runtime.receipts" &&
        command.source === "runtime-projection" &&
        command.route.kind === "primary-view" &&
        command.route.view === "receipts",
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
    index.targets
      .flatMap((target) => target.locators)
      .some(
        (locator) =>
          locator.kind === "data-attribute" &&
          locator.selector === '[data-inspection-target="workspace-editor"]',
      ),
  );
});

test("operator chat chrome remains in chat shell, outside code-editor workspace substrate", () => {
  const operatorChatPane = readFileSync(
    "packages/workspace-substrate/src/components/OperatorChatPane.tsx",
    "utf8",
  );
  const chatConversationSurface = readFileSync(
    "apps/hypervisor/src/windows/ChatShellWindow/components/ChatConversationSurface.tsx",
    "utf8",
  );
  const chatShellWindow = readFileSync(
    "apps/hypervisor/src/windows/ChatShellWindow/index.tsx",
    "utf8",
  );
  const chatInputSection = readFileSync(
    "apps/hypervisor/src/windows/ChatShellWindow/components/ChatInputSection.tsx",
    "utf8",
  );
  const chatInputControls = readFileSync(
    "apps/hypervisor/src/windows/ChatShellWindow/components/ChatInputControls.tsx",
    "utf8",
  );
  const commandMenus = readFileSync(
    "apps/hypervisor/src/components/ui/CommandMenus.css",
    "utf8",
  );
  const codicon = readFileSync(
    "packages/workspace-substrate/src/components/Codicon.tsx",
    "utf8",
  );
  const chatLeftUtilityPane = readFileSync(
    "apps/hypervisor/src/windows/HypervisorShellWindow/components/ChatLeftUtilityPane.tsx",
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
  assert.match(chatConversationSurface, /<OperatorChatPane/);
  assert.match(chatConversationSurface, /id: "new-options"/);
  assert.match(chatConversationSurface, /New Chat \(Ctrl\+N\)/);
  assert.match(chatConversationSurface, /Configure Chat/);
  assert.match(chatConversationSurface, /Views and More Actions\.\.\./);
  assert.match(chatConversationSurface, /Maximize Secondary Side Bar Size/);
  assert.match(chatConversationSurface, /emptyState=\{emptyState\}/);
  assert.match(
    chatConversationSurface,
    /suggestedActions=\{suggestedActions\}/,
  );
  assert.match(chatConversationSurface, /composer=\{composer\}/);
  assert.match(chatShellWindow, /sharedChatEmptyState/);
  assert.match(chatShellWindow, /Build Workspace/);
  assert.match(chatShellWindow, /Show Config/);
  assert.match(chatShellWindow, /Generate Agent Instructions/);
  assert.match(chatShellWindow, /icons\.chatSparkle/);
  assert.match(chatShellWindow, /operator-chat-pane__inline-link/);
  assert.doesNotMatch(chatShellWindow, /<ChatConversationWelcome/);
  assert.match(operatorChatPane, /operator-chat-pane__empty-main/);
  assert.match(operatorChatPane, /operator-chat-pane__suggestions/);
  assert.match(chatShellWindow, /Describe what to build next/);
  assert.doesNotMatch(chatShellWindow, /What do you want to materialize/);
  assert.match(
    chatConversationSurface,
    /dataInspectionTarget="operator-chat-pane"/,
  );
  assert.match(
    chatInputSection,
    /data-inspection-target="operator-chat-composer"/,
  );
  assert.match(chatInputControls, /name="device-desktop"/);
  assert.match(chatInputControls, /name="symbol-operator"/);
  assert.match(chatInputControls, /name="tools"/);
  assert.match(chatInputControls, /aria-label="Select tools"/);
  assert.match(chatInputControls, /onClick=\{onTriggerTools\}/);
  assert.doesNotMatch(chatInputControls, /onClick=\{onToggleAutoContext\}/);
  assert.match(chatInputSection, /activeDropdown === "tools"/);
  assert.match(
    chatInputSection,
    /const toolPaletteMode = commandSurfaceMode === "tools"/,
  );
  assert.match(
    chatInputSection,
    /COMMAND_CENTER_SELECTOR = "\[data-operator-command-center\]"/,
  );
  assert.match(chatInputSection, /useLayoutEffect\(\(\) => \{/);
  assert.match(chatInputSection, /createPortal\(/);
  assert.match(
    chatInputSection,
    /data-inspection-target="operator-command-center-menu"/,
  );
  assert.match(
    chatInputSection,
    /placement=\{searchablePaletteMode \? "command-center" : "composer"\}/,
  );
  assert.match(
    chatInputSection,
    /searchPlaceholder=\{[\s\S]*\? "Select a tool"/,
  );
  assert.match(
    chatInputSection,
    /ariaLabel=\{toolPaletteMode \? "Tool picker"/,
  );
  assert.match(chatInputSection, /id: "tool-manage-capabilities"/);
  assert.match(
    commandMenus,
    /\.spot-slash-menu--palette \.spot-slash-menu-search/,
  );
  assert.match(commandMenus, /\.spot-command-center-menu-overlay/);
  assert.match(commandMenus, /\.spot-slash-menu--command-center/);
  assert.match(commandMenus, /position: fixed/);
  assert.match(commandMenus, /border-radius: 6px/);
  assert.match(commandMenus, /background: #242424/);
  assert.match(commandMenus, /background: #075486/);
  assert.match(chatInputControls, /name="send"/);
  assert.doesNotMatch(chatInputControls, /spot-slash-trigger-text/);
  assert.match(codicon, /codicon-\$\{name\}/);
  assert.match(codicon, /"auxiliarybar-maximize": "screen-full"/);
  assert.match(chatLeftUtilityPane, /Maximize Secondary Side Bar Size/);
  assert.match(chatLeftUtilityPane, /Hide Secondary Side Bar \(Ctrl\+Alt\+B\)/);
  assert.doesNotMatch(chatConversationSurface, /spot-workbench-chat-topbar/);
});

test("workspace adapter commands defer global search to Hypervisor chrome", () => {
  const homeView = readFileSync(
    "apps/hypervisor/src/surfaces/Home/HomeView.tsx",
    "utf8",
  );
  const bundledExtension = readFileSync(
    "workbench-adapters/ioi-code-editor-adapter/extension.js",
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

test("Hypervisor command palette anchors to the header command center", () => {
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
    /COMMAND_CENTER_SELECTOR = "\[data-operator-command-center\]"/,
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
    "apps/hypervisor/src/windows/HypervisorShellWindow/components/ChatLocalActivityBar.tsx",
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

  assert.match(chatHeader, /data-inspection-target="operator-command-center"/);
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
