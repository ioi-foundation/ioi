import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createAutopilotModeController } = require("./mode-controller.js");

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
  return createAutopilotModeController({
    AUTOPILOT_MODE_BY_ID: {
      home: { id: "home" },
      studio: { id: "studio" },
      code: { id: "code" },
    },
    AUTOPILOT_MODE_BY_PANEL_VIEW_ID: {
      "ioi.studio.panel": { id: "studio" },
    },
    AUTOPILOT_MODE_BY_VIEW_ID: {
      "ioi.overview": { id: "home" },
    },
    vscode: fake.vscode,
  });
}

test("Autopilot mode controller maps view ids and tracks code-mode return target", async () => {
  const fake = createFakeVscode();
  const controller = createController(fake);

  assert.equal(controller.modeIdForViewId("ioi.overview"), "home");
  assert.equal(controller.modeIdForViewId("ioi.studio.panel"), "studio");
  assert.equal(controller.modeIdForViewId("unknown"), null);

  controller.setActiveAutopilotMode("studio");
  assert.equal(controller.currentModeId(), "studio");
  assert.equal(controller.lastModeBeforeCode(), "studio");

  controller.setActiveAutopilotMode("code");
  assert.equal(controller.currentModeId(), "code");
  assert.equal(controller.lastModeBeforeCode(), "studio");

  controller.setActiveAutopilotMode("missing");
  assert.equal(controller.currentModeId(), "code");

  await controller.enterAutopilotMode("home");
  assert.equal(controller.currentModeId(), "home");
  assert.equal(controller.lastModeBeforeCode(), "home");
});

test("Autopilot mode controller applies VS Code context and menu chrome", async () => {
  const fake = createFakeVscode();
  const controller = createController(fake);

  await controller.enterAutopilotMode("code");

  assert.deepEqual(fake.commands, [
    ["setContext", "ioi.autopilotMode", false],
    ["setContext", "ioi.codeMode", true],
  ]);
  assert.deepEqual(fake.updates, [
    ["window", "menuBarVisibility", "classic", "global"],
  ]);

  await controller.enterAutopilotMode("studio");
  assert.deepEqual(fake.commands.slice(-2), [
    ["setContext", "ioi.autopilotMode", true],
    ["setContext", "ioi.codeMode", false],
  ]);
  assert.deepEqual(fake.updates.slice(-1), [
    ["window", "menuBarVisibility", "hidden", "global"],
  ]);
});

test("Autopilot mode controller reports failed menu chrome updates without blocking context", async () => {
  const fake = createFakeVscode({ updateRejects: true });
  const controller = createController(fake);
  const lines = [];

  await controller.enterAutopilotMode("studio", { appendLine: (line) => lines.push(line) });

  assert.equal(fake.commands.length, 2);
  assert.equal(lines.length, 1);
  assert.match(lines[0], /unable to update global VS Code menu bar visibility/);
});
