import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const extensionSourcePath =
  "apps/autopilot/openvscode-extension/ioi-workbench/extension.js";
const packageJsonPath =
  "apps/autopilot/openvscode-extension/ioi-workbench/package.json";
const codiconSourcePath =
  "packages/workspace-substrate/src/components/Codicon.tsx";
const desktopLauncherPath = "scripts/launch-autopilot-ide-fork.mjs";

test("native IOI chat view renders the canonical operator chat pane shell", async () => {
  const source = await readFile(extensionSourcePath, "utf8");

  assert.match(source, /data-operator-chat-pane="native-openvscode"/);
  assert.match(source, /data-inspection-target="native-ioi-chat-pane"/);
  assert.match(source, /data-inspection-target="native-ioi-chat-composer"/);
  assert.match(source, /Generate Agent Instructions/);
  assert.match(source, /Build Workspace/);
  assert.match(source, /function renderNativeChatConversation/);
  assert.match(source, /data-inspection-target="native-ioi-chat-thread"/);
  assert.match(source, /data-chat-turn-role/);
  assert.match(source, /state\.chat\?\.turns/);
  assert.match(
    source,
    /label: "Build Workspace",[\s\S]*requestType: "workflow\.codeGenerationRequest"/,
  );
  assert.match(source, /targetWorkspace/);
  assert.match(source, /Show Config/);
  assert.match(source, /requestType: "chat\.submit"/);
});

test("native IOI chat composer uses canonical Autopilot icons and layout tokens", async () => {
  const source = await readFile(extensionSourcePath, "utf8");
  const codiconSource = await readFile(codiconSourcePath, "utf8");
  const canonicalToolsPath = codiconSource.match(
    /<path d="([^"]*M5\.66901[^"]*)"/,
  )?.[1];

  assert.match(source, /function renderNativeChatIcon/);
  assert.ok(canonicalToolsPath);
  assert.match(source, /case "paperclip"/);
  assert.match(source, /case "device-desktop"/);
  assert.match(source, /case "symbol-operator"/);
  assert.match(source, /case "tools"/);
  assert.match(source, /case "send"/);
  assert.match(source, /M7\.25 4\.75v5M4\.75 7\.25h5M14\.25 7\.25h5/);
  assert.match(source, /M5 4\.5 20 12 5 19\.5v-15Z/);
  assert.ok(source.includes(canonicalToolsPath));
  assert.match(source, /class="operator-chat-icon-select"/);
  assert.match(source, /class="operator-chat-tool-toggle"/);
  assert.match(source, /data-bridge-request="commandCenter\.open"/);
  assert.match(source, /data-payload='\{"mode":"tools"\}'/);
  assert.match(source, /data-bridge-request="\$\{escapeHtml\(action\.requestType/);
  assert.doesNotMatch(source, /data-native-tool-picker-button/);
  assert.doesNotMatch(source, /class="operator-chat-tool-menu"/);
  assert.doesNotMatch(source, /data-native-tool-search/);
  assert.doesNotMatch(source, /data-native-tool-item/);
  assert.doesNotMatch(source, /function renderNativeChatToolMenu/);
  assert.doesNotMatch(source, /openNativeToolMenu/);
  assert.doesNotMatch(source, /closeNativeToolMenu/);
  assert.doesNotMatch(source, /data-bridge-request="chat\.toolControls"/);
  assert.match(source, /data-autopilot-theme="\$\{escapeHtml\(appearanceThemeId\)\}"/);
  assert.match(source, /--ioi-operator-chat-accent: #0098ff/);
  assert.match(source, /--operator-chat-accent: var\(\s*--ioi-operator-chat-accent/);
  assert.match(source, /--ioi-operator-chat-selected-border/);
  assert.match(source, /width: min\(100% - 24px, 360px\)/);
  assert.match(source, /enableForms: true/);
  assert.match(source, /this\.lastRenderedHtml = null/);
  assert.match(source, /if \(html === this\.lastRenderedHtml\)/);
  assert.match(source, /autocomplete="off"/);
  assert.match(source, /spellcheck="false"/);
  assert.match(source, /const focusComposerInput = \(\) =>/);
  assert.match(source, /composer\?\.addEventListener\("pointerdown"/);
  assert.match(source, /composerInput\?\.addEventListener\("pointerdown", focusComposerInput\)/);
  assert.match(source, /dataset\.chatMode/);
  assert.match(source, /dataset\.chatModel/);
  assert.doesNotMatch(source, /var\(--vscode-focusBorder\)/);
  assert.doesNotMatch(source, />▱<\/button>|>⌁<\/button>|>♮<\/button>|>▷<\/button>/);
});

test("native IOI chat view routes user actions through bridge requests", async () => {
  const source = await readFile(extensionSourcePath, "utf8");

  assert.match(source, /message\?\.type === "bridgeRequest"/);
  assert.match(source, /writeBridgeRequest\(\s*message\.requestType/);
  assert.match(source, /buildWorkspaceActionContext\("ioi\.chat"\)/);
  assert.match(source, /vscode\.commands\.registerCommand\("ioi\.commandCenter\.open"/);
  assert.match(source, /writeBridgeRequest\("commandCenter\.open"/);
  assert.match(source, /initialQuery/);
  assert.match(source, /typeof options\.mode === "string"[\s\S]*\.\.\.\(mode \? \{ mode \} : \{\}\)/);
  assert.doesNotMatch(source, /createRuntime|new Runtime|reactShadowStore/i);
});

test("native IOI chat title actions are contributed by the IOI extension", async () => {
  const manifest = JSON.parse(await readFile(packageJsonPath, "utf8"));
  const commands = new Set(
    (manifest.contributes?.commands || []).map((command) => command.command),
  );
  const chatContainer = manifest.contributes?.viewsContainers?.secondarySidebar?.find(
    (container) => container.id === "ioi-chat",
  );
  const activityContainers = manifest.contributes?.viewsContainers?.activitybar || [];
  const chatViews = manifest.contributes?.views?.["ioi-chat"] || [];

  assert.equal(chatContainer?.title, " ");
  assert.ok(chatViews.some((view) => view.id === "ioi.chat"));
  assert.ok(chatViews.some((view) => view.id === "ioi.runs"));
  assert.ok(chatViews.some((view) => view.id === "ioi.artifacts"));
  assert.ok(chatViews.some((view) => view.id === "ioi.policy"));
  assert.ok(chatViews.some((view) => view.id === "ioi.connections"));
  assert.ok(!activityContainers.some((container) => container.id === "ioi"));
  assert.ok(
    activityContainers.some(
      (container) =>
        container.id === "ioi-studio" && container.icon === "$(sparkle)",
    ),
  );
  assert.ok(activityContainers.some((container) => container.id === "ioi-workflows"));
  assert.ok(activityContainers.some((container) => container.id === "ioi-models"));
  assert.ok(commands.has("ioi.commandCenter.open"));
  assert.ok(commands.has("ioi.studio.open"));
  assert.ok(commands.has("ioi.studio.agentBuilder"));
  assert.ok(commands.has("ioi.chat.new"));
  assert.ok(commands.has("ioi.chat.newOptions"));
  assert.ok(commands.has("ioi.chat.openSettings"));
  assert.ok(commands.has("ioi.chat.focusComposer"));
  assert.ok(commands.has("ioi.chat.moreActions"));

  const titleCommands = new Set(
    (manifest.contributes?.menus?.["view/title"] || [])
      .filter((item) => item.when === "view == ioi.chat")
      .map((item) => item.command),
  );
  assert.ok(titleCommands.has("ioi.chat.new"));
  assert.ok(titleCommands.has("ioi.chat.newOptions"));
  assert.ok(titleCommands.has("ioi.chat.openSettings"));
  assert.ok(titleCommands.has("ioi.chat.moreActions"));
  assert.ok(!titleCommands.has("ioi.chat.focusComposer"));
});

test("Agent Studio contributes a direct activity surface and landing panel", async () => {
  const source = await readFile(extensionSourcePath, "utf8");
  const manifest = JSON.parse(await readFile(packageJsonPath, "utf8"));
  const studioViews = manifest.contributes?.views?.["ioi-studio"] || [];

  assert.ok(studioViews.some((view) => view.id === "ioi.studio"));
  assert.match(source, /function studioPanelHtml/);
  assert.match(source, /data-testid="agent-studio-landing"/);
  assert.match(source, /<h1>Agent Studio<\/h1>/);
  assert.match(source, /Describe an agent, workflow, or app to build/);
  assert.match(source, /data-command="ioi\.workflow\.openComposer"/);
  assert.match(source, /data-command="ioi\.models\.open"/);
  assert.match(source, /data-command="ioi\.studio\.agentBuilder"/);
  assert.match(source, /requestType: "studio\.promptSubmit"/);
  assert.match(source, /runtimeAuthority: "daemon-owned"/);
  assert.match(source, /projectionOwner: "ioi-workbench-agent-studio"/);
  assert.match(source, /"ioi\.studio": \{\s*command: "ioi\.studio\.open"/);
  assert.match(source, /"ioi\.workflows": \{\s*command: "ioi\.workflow\.openComposer"/);
  assert.match(source, /"ioi\.models": \{\s*command: "ioi\.models\.open"/);
  assert.match(source, /function closePrimarySidebarAfterActivityLaunch/);
  assert.match(source, /ioi-studio\.svg/);
});

test("Autopilot Models renders the LM Studio-inspired operator surface", async () => {
  const source = await readFile(extensionSourcePath, "utf8");
  const manifest = JSON.parse(await readFile(packageJsonPath, "utf8"));
  const commands = new Set(
    (manifest.contributes?.commands || []).map((command) => command.command),
  );
  const modelViews = manifest.contributes?.views?.["ioi-models"] || [];

  assert.ok(modelViews.some((view) => view.id === "ioi.models"));
  assert.ok(commands.has("ioi.models.open"));
  assert.ok(commands.has("ioi.models.openLoader"));
  assert.ok(commands.has("ioi.models.selectForWorkflow"));
  assert.match(source, /models-lmstudio__primary/);
  assert.match(source, /data-testid="model-library-table"/);
  assert.match(source, /data-testid="model-selected-inspector"/);
  assert.match(source, /data-testid="model-quick-loader-popover"/);
  assert.match(source, /data-testid="model-load-dialog"/);
  assert.match(source, /data-testid="model-discover-view"/);
  assert.match(source, /data-testid="model-server-logs"/);
  assert.match(source, /data-testid="model-running-unload-button"/);
  assert.match(source, /data-testid="model-advanced-settings-panel"/);
  assert.match(source, /data-testid="model-estimate-button"/);
  assert.match(source, /data-testid="model-empty-state"/);
  assert.match(source, /data-testid="model-error-state"/);
  assert.match(source, /endpointId: endpoint\?\.id/);
  assert.match(source, /endpointId: selectedEndpoint\.id/);
  assert.match(source, /moveModelSelection/);
  assert.match(source, /data-model-inspector-tab="info"/);
  assert.match(source, /data-model-inspector-tab="load"/);
  assert.match(source, /function activateModelInspectorTab/);
  assert.match(source, /runtimeAuthority: "daemon-owned"/);
  assert.match(source, /webviewExecutesModel: false/);
  assert.doesNotMatch(source, /src-tauri|@tauri-apps|tauri:\/\/|tauri\./i);
});

test("Autopilot desktop launcher starts a daemon sidecar and discovers local models", async () => {
  const source = await readFile(desktopLauncherPath, "utf8");

  assert.match(source, /startRuntimeDaemonService/);
  assert.match(source, /IOI_DAEMON_ENDPOINT/);
  assert.match(source, /IOI_DAEMON_TOKEN/);
  assert.match(source, /AUTOPILOT_SKIP_DAEMON/);
  assert.match(source, /AUTOPILOT_SKIP_MODEL_AUTODISCOVERY/);
  assert.match(source, /AUTOPILOT_SKIP_EXTENSION_SYNC/);
  assert.match(source, /syncWorkbenchExtension/);
  assert.match(source, /syncWorkbenchExtensionTargets/);
  assert.match(source, /provider\.lmstudio/);
  assert.match(source, /\/api\/v1\/providers\/\$\{encodeURIComponent\(providerId\)\}\/models/);
  assert.match(source, /\/api\/v1\/models\/mount/);
  assert.match(source, /route\.native-local/);
  assert.match(source, /autopilot-ide-daemon-ready\.json/);
});

test("Workflow Composer reflects live daemon model route readiness", async () => {
  const composerSource = await readFile(
    "apps/autopilot/openvscode-extension/ioi-workbench/webview/workflow-composer/main.tsx",
    "utf8",
  );
  const runtimeSource = await readFile(
    "apps/autopilot/openvscode-extension/ioi-workbench/webview/workflow-composer/fixtureRuntime.ts",
    "utf8",
  );
  const daemonSource = await readFile("packages/runtime-daemon/src/model-mounting.mjs", "utf8");

  assert.match(composerSource, /daemonModelRouteReady/);
  assert.match(composerSource, /Daemon route blocked/);
  assert.match(composerSource, /data-route-ready/);
  assert.match(runtimeSource, /daemonModelId/);
  assert.match(runtimeSource, /max_tokens: 1/);
  assert.match(daemonSource, /max_tokens: body\.max_tokens/);
  assert.match(daemonSource, /temperature: body\.temperature/);
});

test("native workbench context snapshots are projected to IOI runtime bridge", async () => {
  const source = await readFile(extensionSourcePath, "utf8");

  assert.match(source, /function buildWorkbenchContextSnapshot/);
  assert.match(source, /schemaVersion: "ioi\.workbench-integration\.v1"/);
  assert.match(source, /runtimeTruthSource: "daemon-runtime"/);
  assert.match(source, /projectionOwner: "openvscode-workbench-adapter"/);
  assert.match(source, /ownsRuntimeState: false/);
  assert.match(source, /activeEditor/);
  assert.match(source, /diagnostics/);
  assert.match(source, /terminalState/);
  assert.match(source, /visibleView/);
  assert.match(source, /function buildWorkbenchScmState/);
  assert.match(source, /vscode\.extensions\.getExtension\("vscode\.git"\)/);
  assert.match(source, /workingTreeChanges/);
  assert.match(source, /indexChanges/);
  assert.match(source, /untrackedChanges/);
  assert.match(source, /function buildWorkbenchTaskState/);
  assert.match(source, /vscode\.tasks\.taskExecutions/);
  assert.match(source, /vscode\.tasks\.onDidStartTask/);
  assert.match(source, /vscode\.tasks\.onDidEndTaskProcess/);
  assert.match(source, /writeBridgeRequest\("workbench\.contextSnapshot"/);
  assert.match(source, /startWorkbenchContextSnapshotPublisher\(context, output\)/);
});

test("native inspection target index prefers workbench refs before fallback", async () => {
  const source = await readFile(extensionSourcePath, "utf8");

  assert.match(source, /function buildWorkbenchInspectionTargetIndex/);
  assert.match(source, /indexId: "workbench-target-index:latest"/);
  assert.match(source, /targetId: "ioi\.chat"/);
  assert.match(source, /targetId: "ioi\.chat\.composer"/);
  assert.match(source, /targetId: "ioi\.chat\.action\.build-workspace"/);
  assert.match(source, /targetId: "command-center\.autopilot-header"/);
  assert.match(source, /targetId: "command-center\.openvscode-disabled"/);
  assert.match(source, /targetId: "activity\.studio"/);
  assert.match(source, /targetId: "activity\.workflows"/);
  assert.match(source, /targetId: "activity\.models"/);
  assert.doesNotMatch(source, /targetId: "activity\.ioi"/);
  assert.match(source, /targetId: "activity\.explorer"/);
  assert.match(source, /targetId: "activity\.search"/);
  assert.match(source, /targetId: "activity\.scm"/);
  assert.match(source, /targetId: "explorer\.active-file"/);
  assert.match(source, /targetId: `editor\.tab\.\$\{groupIndex\}\.\$\{tabIndex\}`/);
  assert.match(source, /targetId: "workflow\.composer"/);
  assert.match(source, /targetId: "workflow\.generate-code"/);
  assert.match(source, /targetId: "run\.evidence\.rows"/);
  assert.match(source, /targetId: "checks\.tasks"/);
  assert.match(source, /commandId: "workbench\.view\.extension\.ioi-chat"/);
  assert.match(source, /commandId: "workbench\.view\.extension\.ioi-studio"/);
  assert.match(source, /commandId: "workbench\.view\.extension\.ioi-workflows"/);
  assert.match(source, /commandId: "workbench\.view\.extension\.ioi-models"/);
  assert.match(source, /commandId: "ioi\.workflow\.generateCode"/);
  assert.match(source, /commandId: "ioi\.runs\.refresh"/);
  assert.match(source, /commandId: "workbench\.action\.tasks\.runTask"/);
  assert.match(source, /targetId: "editor\.active"/);
  assert.match(source, /kind: "vscode-command"/);
  assert.match(source, /kind: "vscode-view"/);
  assert.match(source, /kind: "editor-range"/);
  assert.match(source, /writeBridgeRequest\("workbench\.inspectionTargetIndex"/);
});

test("workflow code generation requests are proposal-first runtime projections", async () => {
  const source = await readFile(extensionSourcePath, "utf8");
  const manifest = JSON.parse(await readFile(packageJsonPath, "utf8"));
  const commands = new Set(
    (manifest.contributes?.commands || []).map((command) => command.command),
  );

  assert.ok(commands.has("ioi.workflow.generateCode"));
  assert.match(source, /vscode\.commands\.registerCommand\("ioi\.workflow\.generateCode"/);
  assert.match(source, /requestId: crypto\.randomUUID\(\)/);
  assert.match(source, /runtimeTruthSource: "daemon-runtime"/);
  assert.match(source, /projectionOwner: "openvscode-workbench-adapter"/);
  assert.match(source, /ownsRuntimeState: false/);
  assert.match(source, /boundModelCapabilityRef/);
  assert.match(source, /boundToolCapabilityRefs/);
  assert.match(source, /authorityScope: "workspace\.fs\.proposal"/);
  assert.match(source, /proposalOnly: true/);
  assert.match(source, /writeBridgeRequest\("workflow\.codeGenerationRequest"/);
});

test("native command routing emits IOI route receipts", async () => {
  const source = await readFile(extensionSourcePath, "utf8");

  assert.match(source, /function buildWorkbenchCommandRouteReceipt/);
  assert.match(source, /requestType: "workbench\.commandRouteReceipt"/);
  assert.match(source, /route: "ioi-runtime-action"/);
  assert.match(source, /"editor-local"/);
  assert.match(source, /route: "blocked"/);
  assert.match(source, /runtimeTruthSource: "daemon-runtime"/);
  assert.match(source, /projectionOwner: "openvscode-workbench-adapter"/);
  assert.match(source, /ownsRuntimeState: false/);
  assert.match(source, /isRuntimeActionRequestType\(requestType\)/);
  assert.match(source, /writeWorkbenchCommandRouteReceipt/);
});
