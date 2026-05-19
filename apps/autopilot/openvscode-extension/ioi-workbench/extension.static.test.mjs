import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const extensionSourcePath =
  "apps/autopilot/openvscode-extension/ioi-workbench/extension.js";
const packageJsonPath =
  "apps/autopilot/openvscode-extension/ioi-workbench/package.json";

test("native IOI chat view renders the canonical operator chat pane shell", async () => {
  const source = await readFile(extensionSourcePath, "utf8");

  assert.match(source, /data-operator-chat-pane="native-openvscode"/);
  assert.match(source, /data-inspection-target="native-ioi-chat-pane"/);
  assert.match(source, /data-inspection-target="native-ioi-chat-composer"/);
  assert.match(source, /Generate Agent Instructions/);
  assert.match(source, /Build Workspace/);
  assert.match(
    source,
    /label: "Build Workspace",[\s\S]*requestType: "workflow\.codeGenerationRequest"/,
  );
  assert.match(source, /targetWorkspace/);
  assert.match(source, /Show Config/);
  assert.match(source, /requestType: "chat\.submit"/);
});

test("native IOI chat view routes user actions through bridge requests", async () => {
  const source = await readFile(extensionSourcePath, "utf8");

  assert.match(source, /message\?\.type === "bridgeRequest"/);
  assert.match(source, /writeBridgeRequest\(\s*message\.requestType/);
  assert.match(source, /buildWorkspaceActionContext\("ioi\.chat"\)/);
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
  const chatViews = manifest.contributes?.views?.["ioi-chat"] || [];

  assert.equal(chatContainer?.title, " ");
  assert.ok(chatViews.some((view) => view.id === "ioi.chat"));
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
  assert.match(source, /commandId: "workbench\.view\.extension\.ioi-chat"/);
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
