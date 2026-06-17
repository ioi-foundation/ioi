import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createHypervisorModeController } = require("./mode-controller.js");

function createFakeVscode({ updateRejects = false } = {}) {
  const commands = [];
  const updates = [];
  return {
    commands,
    updates,
    vscode: {
      ConfigurationTarget: { Global: "global" },
      commands: {
        executeCommand: async (...args) => {
          commands.push(args);
        },
      },
      workspace: {
        getConfiguration(section) {
          return {
            update: async (...args) => {
              updates.push([section, ...args]);
              if (updateRejects) {
                throw new Error("cannot update");
              }
            },
          };
        },
      },
    },
  };
}

function createController(fake = createFakeVscode()) {
  return createHypervisorModeController({
    HYPERVISOR_MODE_BY_ID: {
      home: { id: "home" },
      studio: { id: "studio" },
      code: { id: "code" },
    },
    HYPERVISOR_MODE_BY_PANEL_VIEW_ID: {
      "ioi.studio.panel": { id: "studio" },
    },
    HYPERVISOR_MODE_BY_VIEW_ID: {
      "ioi.overview": { id: "home" },
    },
    vscode: fake.vscode,
  });
}

test("Hypervisor mode controller maps view ids and tracks code-mode return target", async () => {
  const fake = createFakeVscode();
  const controller = createController(fake);

  assert.equal(controller.modeIdForViewId("ioi.overview"), "home");
  assert.equal(controller.modeIdForViewId("ioi.studio.panel"), "studio");
  assert.equal(controller.modeIdForViewId("unknown"), null);

  controller.setActiveHypervisorMode("studio");
  assert.equal(controller.currentModeId(), "studio");
  assert.equal(controller.lastModeBeforeCode(), "studio");

  controller.setActiveHypervisorMode("code");
  assert.equal(controller.currentModeId(), "code");
  assert.equal(controller.lastModeBeforeCode(), "studio");

  controller.setActiveHypervisorMode("missing");
  assert.equal(controller.currentModeId(), "code");

  await controller.enterHypervisorMode("home");
  assert.equal(controller.currentModeId(), "home");
  assert.equal(controller.lastModeBeforeCode(), "home");
});

test("Hypervisor mode controller applies VS Code context and menu chrome", async () => {
  const fake = createFakeVscode();
  const controller = createController(fake);

  await controller.enterHypervisorMode("code");

  assert.deepEqual(fake.commands, [
    ["setContext", "ioi.hypervisorMode", false],
    ["setContext", "ioi.codeMode", true],
  ]);
  assert.deepEqual(fake.updates, [
    ["window", "menuBarVisibility", "classic", "global"],
  ]);

  await controller.enterHypervisorMode("studio");
  assert.deepEqual(fake.commands.slice(-2), [
    ["setContext", "ioi.hypervisorMode", true],
    ["setContext", "ioi.codeMode", false],
  ]);
  assert.deepEqual(fake.updates.slice(-1), [
    ["window", "menuBarVisibility", "hidden", "global"],
  ]);
});

test("Hypervisor mode controller reports failed menu chrome updates without blocking context", async () => {
  const fake = createFakeVscode({ updateRejects: true });
  const controller = createController(fake);
  const lines = [];

  await controller.enterHypervisorMode("studio", { appendLine: (line) => lines.push(line) });

  assert.equal(fake.commands.length, 2);
  assert.equal(lines.length, 1);
  assert.match(lines[0], /unable to update global VS Code menu bar visibility/);
});
