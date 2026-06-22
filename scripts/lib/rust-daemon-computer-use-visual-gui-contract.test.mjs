// Ported agent-sdk computer-use visual_gui behavioral loop + observe broker → Rust hypervisor-daemon.
//
// Origin: packages/agent-sdk/test/computer-use.test.mjs ("runtime daemon projects local visual GUI
// observations through thread tool spine" + "runtime daemon brokers read-only visual GUI
// observations for later visual runs" + "observes local visual GUI captures through read-only
// fixture provider"). The Rust daemon's thread tool-invoke route dispatches:
//   - ioi.computer_use.visual_gui          -> the deterministic 11-event read-only visual loop
//   - ioi.computer_use.visual_gui.observe  -> the read-only observation broker (capture + index)
// on top of the canonical kernel lease building block (build_computer_use_lease_request, which
// owns the visual_gui lane / authority scopes / provider resolution).
//
// Faithful-port note: NO real-display capture. visual_gui echoes the caller-supplied governed
// observation refs and indexes the supplied visual targets; the observe broker surfaces governed
// observation artifact refs (artifact_computer_use_visual_*) deterministically. The base64-fixture
// -> artifact bytes served by artifact.read ride the artifact data-plane (a separate cut), so this
// asserts the projection + governed-ref contract, not artifact.read retrieval.

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, test } from "node:test";

import { startRustHypervisorDaemon } from "./rust-hypervisor-daemon.mjs";

const expectedComputerUseEventKinds = [
  "computer_use.environment_selected",
  "computer_use.lease_acquired",
  "computer_use.run_state",
  "computer_use.observation",
  "computer_use.affordance_graph",
  "computer_use.action_proposed",
  "computer_use.action_executed",
  "computer_use.verification",
  "computer_use.commit_gate",
  "computer_use.trajectory_written",
  "computer_use.cleanup",
];

let daemon;
let stateDir;

beforeEach(async () => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-rust-cu-vg-"));
  daemon = await startRustHypervisorDaemon({ stateDir });
});

afterEach(async () => {
  await daemon?.close();
  try {
    fs.rmSync(stateDir, { recursive: true, force: true });
  } catch {
    // best effort
  }
});

async function post(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body ?? {}),
  });
  return { status: response.status, body: await response.json() };
}

async function createThread() {
  const r = await post(`${daemon.endpoint}/v1/threads`, { options: { local: { cwd: stateDir } } });
  assert.equal(r.status, 200);
  return r.body.thread_id || r.body.id;
}

async function readComputerUseEvents(threadId) {
  const text = await (
    await fetch(`${daemon.endpoint}/v1/threads/${threadId}/events`, { headers: { accept: "text/event-stream" } })
  ).text();
  const events = [];
  for (const line of text.split("\n")) {
    if (!line.startsWith("data:")) continue;
    let event;
    try {
      event = JSON.parse(line.slice(5).trim());
    } catch {
      continue;
    }
    if (typeof event.event_kind === "string" && event.event_kind.startsWith("computer_use.")) {
      events.push(event);
    }
  }
  return events;
}

test("Rust ioi.computer_use.visual_gui projects the local visual observation loop", async () => {
  const threadId = await createThread();
  const r = await post(`${daemon.endpoint}/v1/threads/${threadId}/tools/ioi.computer_use.visual_gui/invoke`, {
    source: "react_flow",
    workflowGraphId: "workflow.visual-gui-local-observation",
    workflowNodeId: "visual-gui-local-observation",
    input: {
      prompt: "Inspect the local canvas app.",
      sessionMode: "foreground_desktop",
      actionKind: "inspect",
      observationRetentionMode: "local_redacted_artifacts",
      appName: "Canvas App",
      windowTitle: "Canvas App - Local",
      screenshotRef: "artifact:visual-local:screenshot-redacted",
      somRef: "artifact:visual-local:som",
      axRef: "artifact:visual-local:ax",
      coordinateSpaceId: "screen-visual-local",
      visualTargets: [
        {
          targetRef: "target-local-canvas",
          label: "Main canvas",
          role: "canvas",
          somId: 1,
          confidence: 0.88,
          bounds: { x: 10, y: 20, width: 500, height: 360, coordinateSpaceId: "screen-visual-local" },
          availableActions: ["inspect"],
        },
      ],
    },
  });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const result = r.body;
  assert.equal(result.status, "completed");
  assert.equal(result.object, "ioi.runtime_computer_use_visual_gui_result");
  assert.equal(result.tool_name, "ioi.computer_use.visual_gui");
  assert.equal(result.workflow_graph_id, "workflow.visual-gui-local-observation");
  assert.equal(result.workflow_node_id, "visual-gui-local-observation");
  assert.equal(result.event_count, expectedComputerUseEventKinds.length);

  const view = result.result;
  assert.equal(view.environmentSelection.selected_lane, "visual_gui");
  assert.equal(view.environmentSelection.selected_session_mode, "foreground_desktop");
  assert.equal(view.lease.status, "active");
  assert.equal(view.lease.authority_scope, "computer_use.visual_gui.read");
  assert.equal(view.runState.user_goal, "Inspect the local canvas app.");
  assert.equal(
    view.runState.current_subgoal,
    "Observe the requested surface, index targets, and propose a grounded next action.",
  );
  assert.equal(view.observation.screenshot_ref, "artifact:visual-local:screenshot-redacted");
  assert.equal(view.observation.som_ref, "artifact:visual-local:som");
  assert.equal(view.observation.ax_ref, "artifact:visual-local:ax");
  assert.equal(view.targetIndex.coordinate_space_id, "screen-visual-local");
  assert.equal(view.targetIndex.targets[0].target_ref, "target-local-canvas");
  assert.equal(view.affordanceGraph.affordances[0].required_authority, "computer_use.visual_gui.read");
  assert.equal(view.action.action_kind, "inspect");
  assert.equal(view.actionReceipt.adapter_id, "ioi.visual_gui.local_observation");
  assert.equal(view.verification.status, "passed");
  assert.ok(view.trajectory.entries[0].summary.includes("visual"));
  assert.deepEqual(view.cleanup.retained_artifact_refs, [
    "computer-use-trace.json",
    "artifact:visual-local:screenshot-redacted",
    "artifact:visual-local:som",
    "artifact:visual-local:ax",
  ]);

  const events = await readComputerUseEvents(threadId);
  assert.deepEqual(
    events.map((event) => event.event_kind),
    expectedComputerUseEventKinds,
  );
  const selected = events[0];
  assert.equal(selected.payload.computer_use_lane, "visual_gui");
  assert.equal(selected.payload.computer_use_contract_ingest, "local_visual_observation");
  const observation = events[3];
  assert.equal(observation.event_kind, "computer_use.observation");
  assert.equal(observation.payload.observation_bundle.screenshot_ref, "artifact:visual-local:screenshot-redacted");
  assert.equal(observation.payload.target_index.targets[0].target_ref, "target-local-canvas");
});

test("Rust ioi.computer_use.visual_gui.observe brokers a read-only fixture capture", async () => {
  const threadId = await createThread();
  const r = await post(
    `${daemon.endpoint}/v1/threads/${threadId}/tools/ioi.computer_use.visual_gui.observe/invoke`,
    {
      source: "sdk_test",
      workflowGraphId: "workflow.visual-gui-capture",
      workflowNodeId: "visual-gui-capture",
      toolCallId: "capture_fixture",
      input: {
        prompt: "Capture the current local workflow composer surface.",
        captureScreen: true,
        captureAxTree: true,
        captureProvider: "fixture",
        captureFixturePngBase64:
          "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAFgwJ/l6eI2wAAAABJRU5ErkJggg==",
        captureFixtureAxTree: { role: "window", name: "Workflow Composer" },
        captureAppName: "Hypervisor",
        captureWindowTitle: "Workflow Composer",
        sessionMode: "foreground_desktop",
      },
    },
  );
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const observe = r.body;
  assert.equal(observe.status, "completed");
  assert.equal(observe.object, "ioi.runtime_computer_use_visual_gui_observe_result");
  const view = observe.result;
  assert.equal(view.action.action_kind, "inspect");
  assert.equal(view.lease.authority_scope, "computer_use.visual_gui.read");
  assert.equal(view.observation.app_name, "Hypervisor");
  assert.equal(view.observation.window_title, "Workflow Composer");
  assert.match(view.observation.screenshot_ref, /^artifact_computer_use_visual_/);
  assert.match(view.observation.ax_ref, /^artifact_computer_use_visual_/);
  assert.equal(view.targetIndex.coordinate_space_id, "screen_capture_fixture_local_capture");
  assert.equal(view.targetIndex.targets[0].bounds.width, 1);
  assert.equal(view.targetIndex.targets[0].bounds.height, 1);
  assert.deepEqual(view.targetIndex.targets[0].available_actions, ["inspect"]);
  assert.equal(view.observationBroker.capture_receipt.status, "captured");
  assert.equal(view.observationBroker.capture_receipt.provider_id, "fixture");
  assert.equal(view.observationBroker.capture_receipt.source_path_included, false);
  assert.ok(view.cleanup.retained_artifact_refs.includes(view.observation.screenshot_ref));
});

test("Rust ioi.computer_use.visual_gui fails closed for an unknown thread (404)", async () => {
  const r = await post(
    `${daemon.endpoint}/v1/threads/thread_missing/tools/ioi.computer_use.visual_gui/invoke`,
    { input: { prompt: "Inspect" } },
  );
  assert.equal(r.status, 404);
});
