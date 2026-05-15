import assert from "node:assert/strict";
import test from "node:test";

import type { WorkflowProject } from "../types/graph";
import { workflowNodeCreatorDefinitions } from "../runtime/workflow-node-registry";
import {
  WORKFLOW_COMPOSER_COMPUTER_USE_RUN_OPTIONS_SCHEMA_VERSION,
  mergeWorkflowComposerComputerUseRunOptions,
  workflowComposerComputerUseRunOptions,
} from "./computerUseRunOptions";

test("computer-use composer run options project browser-use preset metadata", () => {
  const workflow = workflowWithCreator("plugin_tool.browser_use");
  const options = workflowComposerComputerUseRunOptions(workflow);

  assert.ok(options);
  assert.deepEqual(options.metadata, {
    schemaVersion: WORKFLOW_COMPOSER_COMPUTER_USE_RUN_OPTIONS_SCHEMA_VERSION,
    source: "react_flow_workflow",
    computerUse: true,
    computerUseLane: "native_browser",
    computerUseSessionMode: "owned_hermetic_browser",
    computerUseActionKind: "inspect",
    observationRetentionMode: "local_redacted_artifacts",
    failClosedWhenUnavailable: true,
    workflowGraphId: "workflow.computer-use-test",
    workflowNodeId: "node-plugin_tool-browser_use",
    workflowNodeIds: ["node-plugin_tool-browser_use"],
    toolRef: "ioi.computer_use.native_browser",
    authorityScopes: [
      "computer_use.native_browser.read",
      "computer_use.action_proposal",
      "computer_use.cleanup",
    ],
  });
});

test("computer-use composer run options project sandboxed preset metadata", () => {
  const options = workflowComposerComputerUseRunOptions(
    workflowWithCreator("plugin_tool.computer_use.sandboxed"),
  );

  assert.ok(options);
  assert.equal(options.metadata.computerUseLane, "sandboxed_hosted");
  assert.equal(options.metadata.computerUseSessionMode, "hosted_sandbox");
  assert.equal(options.metadata.observationRetentionMode, "no_persistence");
  assert.equal(options.metadata.failClosedWhenUnavailable, true);
  assert.equal(options.metadata.toolRef, "ioi.computer_use.sandboxed_hosted");
});

test("computer-use composer run options project configured native-browser action kind", () => {
  const workflow = workflowWithCreator("plugin_tool.browser_use");
  const first = workflow.nodes[0];
  const args = first.config?.logic?.toolBinding?.arguments as Record<string, unknown>;
  args["computerUseActionKind"] = "click";
  args["computerUseApprovalRef"] = "approval-browser-click";
  args["targetRef"] = "#submit";
  args["selector"] = "#submit";
  args["text"] = "hello";
  args["key"] = "Enter";
  args["scrollY"] = 420;
  args["filePath"] = "/tmp/upload.txt";
  args["cdpEndpointUrl"] = "http://127.0.0.1:9222";
  args["cdpTimeoutMs"] = 5000;
  args["computerUseSessionMode"] = "controlled_relaunch";
  args["controlledRelaunchApprovalRef"] = "approval-controlled-browser-launch";
  args["controlledRelaunchBrokerRef"] = "broker-controlled-browser-launch";
  args["controlledRelaunchExecutablePath"] = "/usr/bin/chromium";
  args["controlledRelaunchHeadless"] = true;
  args["controlledRelaunchStartUrl"] = "https://example.test";
  args["controlledRelaunchCdpPort"] = 9223;

  const options = workflowComposerComputerUseRunOptions(workflow);

  assert.ok(options);
  assert.equal(options.metadata.computerUseSessionMode, "controlled_relaunch");
  assert.equal(options.metadata.computerUseActionKind, "click");
  assert.equal(options.metadata.computerUseApprovalRef, "approval-browser-click");
  assert.equal(options.metadata.computerUseTargetRef, "#submit");
  assert.equal(
    options.metadata.controlledRelaunchApprovalRef,
    "approval-controlled-browser-launch",
  );
  assert.equal(
    options.metadata.controlledRelaunchBrokerRef,
    "broker-controlled-browser-launch",
  );
  assert.equal(options.metadata.controlledRelaunchExecutablePath, "/usr/bin/chromium");
  assert.equal(options.metadata.controlledRelaunchHeadless, true);
  assert.equal(options.metadata.controlledRelaunchStartUrl, "https://example.test");
  assert.equal(options.metadata.controlledRelaunchCdpPort, 9223);
  assert.equal(options.metadata.selector, "#submit");
  assert.equal(options.metadata.text, "hello");
  assert.equal(options.metadata.key, "Enter");
  assert.equal(options.metadata.scrollY, 420);
  assert.equal(options.metadata.filePath, "/tmp/upload.txt");
  assert.equal(options.metadata.cdpEndpointUrl, "http://127.0.0.1:9222");
  assert.equal(options.metadata.cdpTimeoutMs, 5000);
});

test("computer-use composer run options preserve existing run metadata", () => {
  const computerUseOptions = workflowComposerComputerUseRunOptions(
    workflowWithCreator("plugin_tool.computer_use.visual_gui"),
  );
  const merged = mergeWorkflowComposerComputerUseRunOptions(
    {
      threadId: "thread-mounted-model",
      liveTelemetryHydration: true,
      metadata: {
        selectedModelId: "mounted.deepseek",
        prompt: "Open the app and validate the run trace",
      },
    },
    computerUseOptions,
  );

  assert.equal(merged["threadId"], "thread-mounted-model");
  assert.equal(merged["liveTelemetryHydration"], true);
  assert.deepEqual(merged["metadata"], {
    selectedModelId: "mounted.deepseek",
    prompt: "Open the app and validate the run trace",
    schemaVersion: WORKFLOW_COMPOSER_COMPUTER_USE_RUN_OPTIONS_SCHEMA_VERSION,
    source: "react_flow_workflow",
    computerUse: true,
    computerUseLane: "visual_gui",
    computerUseSessionMode: "visual_fallback",
    computerUseActionKind: "inspect",
    observationRetentionMode: "local_redacted_artifacts",
    failClosedWhenUnavailable: true,
    workflowGraphId: "workflow.computer-use-test",
    workflowNodeId: "node-plugin_tool-computer_use-visual_gui",
    workflowNodeIds: ["node-plugin_tool-computer_use-visual_gui"],
    toolRef: "ioi.computer_use.visual_gui",
    authorityScopes: [
      "computer_use.visual_gui.observe",
      "computer_use.visual_gui.propose_action",
      "computer_use.cleanup",
    ],
  });
});

test("computer-use composer run options project visual GUI observation refs", () => {
  const workflow = workflowWithCreator("plugin_tool.computer_use.visual_gui");
  const first = workflow.nodes[0];
  const args = first.config?.logic?.toolBinding?.arguments as Record<string, unknown>;
  args["computerUseSessionMode"] = "foreground_desktop";
  args["screenshotRef"] = "artifact:visual:screenshot-redacted";
  args["somRef"] = "artifact:visual:som";
  args["axRef"] = "artifact:visual:ax";
  args["appName"] = "Canvas App";
  args["windowTitle"] = "Canvas App - Local";
  args["coordinateSpaceId"] = "screen-visual-local";
  args["viewportWidth"] = 1200;
  args["viewportHeight"] = 800;

  const options = workflowComposerComputerUseRunOptions(workflow);

  assert.ok(options);
  assert.equal(options.metadata.computerUseLane, "visual_gui");
  assert.equal(options.metadata.computerUseSessionMode, "foreground_desktop");
  assert.equal(options.metadata.screenshotRef, "artifact:visual:screenshot-redacted");
  assert.equal(options.metadata.somRef, "artifact:visual:som");
  assert.equal(options.metadata.axRef, "artifact:visual:ax");
  assert.equal(options.metadata.appName, "Canvas App");
  assert.equal(options.metadata.windowTitle, "Canvas App - Local");
  assert.equal(options.metadata.coordinateSpaceId, "screen-visual-local");
  assert.equal(options.metadata.viewportWidth, 1200);
  assert.equal(options.metadata.viewportHeight, 800);
});

test("computer-use composer run options ignore non computer-use workflows", () => {
  const options = workflowComposerComputerUseRunOptions(
    workflowWithCreator("plugin_tool.coding_pack"),
  );

  assert.equal(options, null);
});

function workflowWithCreator(creatorId: string): WorkflowProject {
  const creator = workflowNodeCreatorDefinitions().find(
    (candidate) => candidate.creatorId === creatorId,
  );
  if (!creator) {
    throw new Error(`Missing workflow node creator ${creatorId}`);
  }
  const nodeId = `node-${creatorId.replace(/\./g, "-")}`;
  return {
    version: "workflow.v1",
    metadata: {
      id: "workflow.computer-use-test",
      name: "Computer use test",
      slug: "computer-use-test",
      workflowKind: "agent_workflow",
      executionMode: "local",
      gitLocation: ".agents/workflows/computer-use-test.workflow.json",
    },
    nodes: [
      {
        id: nodeId,
        type: "plugin_tool",
        name: creator.label,
        config: {
          logic: creator.defaultLogic,
          law: creator.defaultLaw ?? {},
        },
      },
    ],
    edges: [],
    global_config: {},
  } as unknown as WorkflowProject;
}
