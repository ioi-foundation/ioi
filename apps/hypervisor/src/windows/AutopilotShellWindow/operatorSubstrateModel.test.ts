import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
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

const RETIRED_NATIVE_APP_PATH = ["apps/hypervisor", "src-tauri"].join("/");
const LEGACY_NATIVE_ARCHIVE_SRC_PATH = [
  "internal-docs/legacy",
  "autopilot-tauri-src",
  "src",
].join("/");

test("retired native app path stays archived only", () => {
  assert.equal(existsSync(RETIRED_NATIVE_APP_PATH), false);
  assert.equal(
    existsSync(`${LEGACY_NATIVE_ARCHIVE_SRC_PATH}/workspace_ide.rs`),
    true,
  );
  assert.equal(
    existsSync(`${LEGACY_NATIVE_ARCHIVE_SRC_PATH}/workspace_direct_webview.rs`),
    true,
  );
});

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
  assert.equal(model.scopeLabel, "Autopilot Core / Workbench");
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
      "sessions",
      "projects",
      "missions",
      "workbench",
      "automations",
      "insights",
      "agents",
      "models",
      "privacy",
      "fleet",
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
    model.items.find((item) => item.dataWindowSurface === "fleet")?.routeState,
    "planned_surface",
  );
  assert.equal(
    model.items.find((item) => item.dataWindowSurface === "fleet")?.group,
    "governance",
  );
  assert.equal(
    model.items.find((item) => item.dataWindowSurface === "search")?.route.kind,
    "command-palette",
  );
});

test("operator substrate code does not introduce runtime ownership", () => {
  const source = readFileSync(
    "apps/hypervisor/src/windows/AutopilotShellWindow/operatorSubstrateModel.ts",
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

test("workspace embedding defers global command center to HypervisorClientHeader", () => {
  const workspaceHost = readFileSync(
    "packages/workspace-substrate/src/components/WorkspaceHost.tsx",
    "utf8",
  );
  const workspaceShell = readFileSync(
    "apps/hypervisor/src/surfaces/Workspace/WorkspaceShell.tsx",
    "utf8",
  );
  const openVsCodeDirectSurface = readFileSync(
    "apps/hypervisor/src/surfaces/Workspace/OpenVsCodeDirectSurface.tsx",
    "utf8",
  );
  const workspaceDirectWebview = readFileSync(
    `${LEGACY_NATIVE_ARCHIVE_SRC_PATH}/workspace_direct_webview.rs`,
    "utf8",
  );
  const legacyWorkspaceEditorHost = readFileSync(
    `${LEGACY_NATIVE_ARCHIVE_SRC_PATH}/workspace_ide.rs`,
    "utf8",
  );
  const workspaceRuntimeNavigation = readFileSync(
    "apps/hypervisor/src/services/workspaceRuntimeNavigation.ts",
    "utf8",
  );
  const workspaceBridgeLifecycle = readFileSync(
    "apps/hypervisor/src/services/workspaceBridgeLifecycle.ts",
    "utf8",
  );
  const chatHeader = readFileSync(
    "apps/hypervisor/src/windows/AutopilotShellWindow/components/HypervisorClientHeader.tsx",
    "utf8",
  );
  const shellContent = readFileSync(
    "apps/hypervisor/src/windows/AutopilotShellWindow/components/AutopilotShellContent.tsx",
    "utf8",
  );
  const shellWindow = readFileSync(
    "apps/hypervisor/src/windows/AutopilotShellWindow/index.tsx",
    "utf8",
  );
  const shellController = readFileSync(
    "apps/hypervisor/src/windows/AutopilotShellWindow/useAutopilotShellController.ts",
    "utf8",
  );
  assert.match(workspaceHost, /hideGlobalCommandCenter\?: boolean/);
  assert.match(workspaceHost, /workspace-host--global-command-center-hidden/);
  assert.match(workspaceShell, /hideGlobalCommandCenter/);
  assert.match(workspaceShell, /operatorChatPane\?: ReactNode/);
  assert.match(workspaceShell, /operatorChatPaneWidthPx\?: number/);
  assert.match(workspaceShell, /directSurfaceReservedRightPx/);
  assert.match(
    workspaceShell,
    /reservedRightPx=\{directSurfaceReservedRightPx\}/,
  );
  assert.match(workspaceShell, /mode\?: "default" \| "tools"/);
  assert.match(workspaceShell, /chat-workspace-oss-shell__operator-chat-slot/);
  assert.match(openVsCodeDirectSurface, /reservedRightPx\?: number/);
  assert.match(openVsCodeDirectSurface, /suspended\?: boolean/);
  assert.match(openVsCodeDirectSurface, /const visible = active && !suspended/);
  assert.match(
    openVsCodeDirectSurface,
    /hideWorkspaceDirectWebview\(surface\.surfaceId\)/,
  );
  assert.match(openVsCodeDirectSurface, /readElementBoundsWithReservedRight/);
  assert.match(openVsCodeDirectSurface, /constrainBoundsForReservedRight/);
  assert.match(openVsCodeDirectSurface, /surfaceWidth - reservedRightWidth/);
  assert.match(
    openVsCodeDirectSurface,
    /\[reservedRightPx, scheduleSettledSyncBounds, visible\]/,
  );
  assert.match(workspaceDirectWebview, /bounds\.width\.min\(max_width\)/);
  assert.match(workspaceDirectWebview, /clamped child bounds/);
  assert.match(legacyWorkspaceEditorHost, /"ioi\.commandCenter\.open"/);
  assert.match(
    workspaceRuntimeNavigation,
    /case "commandCenter\.open":[\s\S]*onOpenCommandPalette\?\.\(/,
  );
  assert.match(
    workspaceRuntimeNavigation,
    /readString\(request\.payload, "mode"\) === "tools" \? "tools" : "default"/,
  );
  assert.match(
    workspaceRuntimeNavigation,
    /readString\(request\.payload, "initialQuery"\) \?\? undefined,\s*requestedMode/,
  );
  assert.match(
    workspaceBridgeLifecycle,
    /routeHandlers\?: WorkspaceBridgeRouteHandlers[\s\S]*params\.routeHandlers/,
  );
  assert.match(shellContent, /const workspaceOperatorChatPane/);
  assert.match(shellContent, /workspaceUsesNativeWorkbenchChat/);
  assert.match(shellContent, /workspaceHost === directWorkspaceWorkbenchHost/);
  assert.match(shellContent, /workspaceHost === openVsCodeWorkbenchHost/);
  assert.match(shellContent, /operatorChatPane=\{workspaceOperatorChatPane\}/);
  assert.match(
    shellContent,
    /commandPaletteOpen=\{controller\.modals\.commandPaletteOpen\}/,
  );
  assert.match(
    shellContent,
    /onOpenCommandPalette=\{controller\.modals\.openCommandPalette\}/,
  );
  assert.match(shellWindow, /mode=\{controller\.modals\.commandPaletteMode\}/);
  assert.match(shellController, /useState<"default" \| "tools">\("default"\)/);
  assert.match(
    shellController,
    /mode: "default" \| "tools" = "default"[\s\S]*setCommandPaletteMode\(mode\)/,
  );
  assert.match(chatHeader, /data-operator-command-center/);
});

test("direct OpenVSCode workspace failures stay in integrated surface chrome", () => {
  const workspaceShell = readFileSync(
    "apps/hypervisor/src/surfaces/Workspace/WorkspaceShell.tsx",
    "utf8",
  );
  const workspaceStyles = readFileSync(
    "apps/hypervisor/src/windows/AutopilotShellWindow/styles/autopilot-shell/trace-and-welcome.css",
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
  const workspacePanelStyles = readFileSync(
    "packages/workspace-substrate/src/style/workspace-panels.css",
    "utf8",
  );
  const codicon = readFileSync(
    "packages/workspace-substrate/src/components/Codicon.tsx",
    "utf8",
  );
  const chatLeftUtilityPane = readFileSync(
    "apps/hypervisor/src/windows/AutopilotShellWindow/components/ChatLeftUtilityPane.tsx",
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
  assert.match(workspaceHost, /id: "new-options"/);
  assert.match(workspaceHost, /New Chat \(Ctrl\+N\)/);
  assert.match(workspaceHost, /Configure Chat/);
  assert.match(workspaceHost, /Views and More Actions\.\.\./);
  assert.match(workspaceHost, /Hide Secondary Side Bar \(Ctrl\+Alt\+B\)/);
  assert.match(workspaceHost, /Build Workspace/);
  assert.match(workspaceHost, /Show Config/);
  assert.match(workspaceHost, /Generate Agent Instructions/);
  assert.match(workspaceHost, /operator-chat-pane__inline-link/);
  assert.match(workspaceHost, /AI responses may be inaccurate\./);
  assert.doesNotMatch(
    workspaceHost,
    /Repo, file, runtime, and evidence context stay attached/,
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
  assert.match(
    workspaceHost,
    /className="workspace-agent-composer-tool-toggle"/,
  );
  assert.match(workspaceHost, /className="workspace-agent-tool-menu"/);
  assert.match(workspaceHost, /aria-label="Select a tool"/);
  assert.match(workspaceHost, /value=\{toolMenuQuery\}/);
  assert.match(workspaceHost, /No matching tools/);
  assert.match(workspaceHost, /surface: "connections"/);
  assert.doesNotMatch(workspaceHost, /placeholder="Select a tool" readOnly/);
  assert.doesNotMatch(
    workspaceHost,
    /aria-label="Workspace chat tools"[\s\S]*onClick=\{\(\) => onOpenSurface\?\.\("policy"\)\}/,
  );
  assert.match(workspacePanelStyles, /\.workspace-agent-tool-menu/);
  assert.match(workspacePanelStyles, /\.workspace-agent-tool-menu__empty/);
  assert.match(codicon, /codicon-\$\{name\}/);
  assert.match(codicon, /"auxiliarybar-maximize": "screen-full"/);
  assert.match(chatLeftUtilityPane, /Maximize Secondary Side Bar Size/);
  assert.match(chatLeftUtilityPane, /Hide Secondary Side Bar \(Ctrl\+Alt\+B\)/);
  assert.doesNotMatch(chatConversationSurface, /spot-workbench-chat-topbar/);
  assert.doesNotMatch(workspaceHost, /function WorkbenchAgentDock/);
  assert.doesNotMatch(workspaceHost, /workspace-agent-dock-header-hitbox/);
  assert.doesNotMatch(workspaceHost, /workspace-agent-dock-hitbox/);
  assert.doesNotMatch(workspaceHost, /workbenchDockHeaderFullStrip/);
  assert.doesNotMatch(workspaceHost, /workbenchDockBodyStrip/);
});

test("embedded OpenVSCode defers global search to Hypervisor chrome", () => {
  const legacyWorkspaceEditorHost = readFileSync(
    `${LEGACY_NATIVE_ARCHIVE_SRC_PATH}/workspace_ide.rs`,
    "utf8",
  );
  const homeView = readFileSync(
    "apps/hypervisor/src/surfaces/Home/HomeView.tsx",
    "utf8",
  );
  const homeOnboardingModel = readFileSync(
    "apps/hypervisor/src/surfaces/Home/homeOnboardingModel.ts",
    "utf8",
  );
  const bundledExtension = readFileSync(
    "workbench-adapters/ioi-workbench/extension.js",
    "utf8",
  );

  assert.match(
    legacyWorkspaceEditorHost,
    /"window\.commandCenter"\.to_string\(\),\s*Value::Bool\(false\)/,
  );
  assert.match(
    legacyWorkspaceEditorHost,
    /"window\.customTitleBarVisibility"\.to_string\(\),\s*Value::String\("never"\.to_string\(\)\)/,
  );
  assert.match(
    legacyWorkspaceEditorHost,
    /"workbench\.navigationControl\.enabled"\.to_string\(\),\s*Value::Bool\(false\)/,
  );
  assert.match(
    legacyWorkspaceEditorHost,
    /"chat\.agentsControl\.enabled"\.to_string\(\),\s*Value::Bool\(false\)/,
  );
  assert.match(
    legacyWorkspaceEditorHost,
    /"chat\.unifiedAgentsBar\.enabled"\.to_string\(\),\s*Value::Bool\(false\)/,
  );
  assert.match(
    legacyWorkspaceEditorHost,
    /"workbench\.experimental\.share\.enabled"\.to_string\(\),\s*Value::Bool\(false\)/,
  );
  assert.match(
    legacyWorkspaceEditorHost,
    /fn ensure_openvscode_user_keybindings[\s\S]*"-workbench\.action\.quickOpen"[\s\S]*"-workbench\.action\.showCommands"/,
  );
  assert.match(
    legacyWorkspaceEditorHost,
    /fn openvscode_user_config_owned[\s\S]*"window\.commandCenter"[\s\S]*workbench\.action\.quickOpen/,
  );
  assert.match(
    legacyWorkspaceEditorHost,
    /fn ensure_openvscode_legacy_shell_chrome_patch_removed[\s\S]*remove_openvscode_legacy_stylesheet_chrome_patch/,
  );
  assert.match(
    legacyWorkspaceEditorHost,
    /fn ensure_openvscode_native_workbench_js_patch[\s\S]*patch_openvscode_native_workbench_js/,
  );
  assert.match(
    legacyWorkspaceEditorHost,
    /OPENVSCODE_COMMAND_CENTER_GETTER_PATCHED:\s*&str\s*=\s*"get ec\(\)\{return!1\}"/,
  );
  assert.match(
    legacyWorkspaceEditorHost,
    /OPENVSCODE_COMMAND_CENTER_CONTRIBUTION_PATCHED:[\s\S]*data-ioi-native-command-center-disabled/,
  );
  assert.match(
    legacyWorkspaceEditorHost,
    /patch_openvscode_native_workbench_js[\s\S]*OPENVSCODE_COMMAND_CENTER_CONTRIBUTION_SOURCE[\s\S]*OPENVSCODE_COMMAND_CENTER_CONTRIBUTION_PATCHED/,
  );
  assert.doesNotMatch(legacyWorkspaceEditorHost, /stylesheet\.push_str/);
  assert.doesNotMatch(
    legacyWorkspaceEditorHost,
    /\.titlebar-center[\s\S]*display: none !important/,
  );
  assert.match(
    legacyWorkspaceEditorHost,
    /"workbench\.secondarySideBar\.defaultVisibility"\.to_string\(\),\s*Value::String\("visible"\.to_string\(\)\)/,
  );
  assert.match(
    legacyWorkspaceEditorHost,
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
  assert.match(
    bundledExtension,
    /syncAppearanceFromBridge[\s\S]*syncWorkbenchAppearance/,
  );
});

test("Autopilot command palette anchors to the header command center", () => {
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
    "apps/hypervisor/src/windows/AutopilotShellWindow/components/HypervisorClientHeader.tsx",
    "utf8",
  );
  const activityRail = readFileSync(
    "apps/hypervisor/src/windows/AutopilotShellWindow/components/ChatLocalActivityBar.tsx",
    "utf8",
  );
  const directSurface = readFileSync(
    "apps/hypervisor/src/surfaces/Workspace/OpenVsCodeDirectSurface.tsx",
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
    "apps/hypervisor/src/surfaces/Capabilities/components/useCapabilitiesController.ts",
    "utf8",
  );

  assert.match(capabilitiesController, /listenIfHostBridge/);
  assert.doesNotMatch(capabilitiesController, /from "@[^"]*tauri[^"]*"/i);
});
