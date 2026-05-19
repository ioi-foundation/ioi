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
  assert.ok(commands.has("ioi.chat.new"));
  assert.ok(commands.has("ioi.chat.openSettings"));
  assert.ok(commands.has("ioi.chat.focusComposer"));

  const titleCommands = new Set(
    (manifest.contributes?.menus?.["view/title"] || [])
      .filter((item) => item.when === "view == ioi.chat")
      .map((item) => item.command),
  );
  assert.ok(titleCommands.has("ioi.chat.new"));
  assert.ok(titleCommands.has("ioi.chat.openSettings"));
  assert.ok(titleCommands.has("ioi.chat.focusComposer"));
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
  assert.match(source, /writeBridgeRequest\("workbench\.contextSnapshot"/);
  assert.match(source, /startWorkbenchContextSnapshotPublisher\(context, output\)/);
});

test("native inspection target index prefers workbench refs before fallback", async () => {
  const source = await readFile(extensionSourcePath, "utf8");

  assert.match(source, /function buildWorkbenchInspectionTargetIndex/);
  assert.match(source, /indexId: "workbench-target-index:latest"/);
  assert.match(source, /targetId: "ioi\.chat"/);
  assert.match(source, /targetId: "ioi\.chat\.composer"/);
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
