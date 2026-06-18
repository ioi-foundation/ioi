import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const paths = {
  extension: "workbench-adapters/ioi-code-editor-adapter/extension.js",
  packageJson: "workbench-adapters/ioi-code-editor-adapter/package.json",
  bridge: "workbench-adapters/ioi-code-editor-adapter/bridge/workspace-bridge.js",
  client: "workbench-adapters/ioi-code-editor-adapter/bridge/client.js",
  actionContext: "workbench-adapters/ioi-code-editor-adapter/editor-context/action-context.js",
  contextPublisher: "workbench-adapters/ioi-code-editor-adapter/editor-context/context-publisher.js",
  contextSnapshot: "workbench-adapters/ioi-code-editor-adapter/editor-context/context-snapshot.js",
};

async function read(path) {
  return readFile(path, "utf8");
}

test("ioi-code-editor-adapter is a code editor adapter, not a Hypervisor product shell", async () => {
  const [extension, packageRaw] = await Promise.all([
    read(paths.extension),
    read(paths.packageJson),
  ]);
  const packageJson = JSON.parse(packageRaw);

  assert.equal(packageJson.description, "IOI-native code editor adapter for Hypervisor sessions.");
  assert.equal(packageJson.displayName, "IOI Code Adapter");
  assert.deepEqual(packageJson.activationEvents, [
    "onStartupFinished",
    "onCommand:ioi.code.open",
  ]);
  assert.deepEqual(
    packageJson.contributes.commands.map((command) => command.command),
    ["ioi.code.open"],
  );
  assert.equal(packageJson.contributes.views, undefined);
  assert.equal(packageJson.contributes.viewsContainers, undefined);

  assert.match(extension, /startCodeEditorContextPublisher/);
  assert.match(extension, /createCodeEditorContextSnapshot/);
  assert.match(extension, /ioi\.code\.open/);
});

test("adapter bridge and context files keep daemon ownership without product shell state", async () => {
  const composite = await Promise.all([
    read(paths.bridge),
    read(paths.actionContext),
    read(paths.contextPublisher),
    read(paths.contextSnapshot),
    read(paths.client),
  ]).then((parts) => parts.join("\n"));

  assert.match(composite, /runtimeTruthSource: "daemon-runtime"/);
  assert.match(composite, /projectionOwner: "hypervisor-code-editor-adapter"/);
  assert.match(composite, /ownsRuntimeState: false/);
  assert.match(composite, /activeEditor/);
  assert.match(composite, /diagnostics/);
  assert.match(composite, /terminalState/);
  assert.match(composite, /codeEditor\.contextSnapshot/);
  assert.match(composite, /codeEditor\.inspectionTargetIndex/);
});
