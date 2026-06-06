import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  captureLocalVisualGuiObservation,
  visualGuiLocalCaptureRequested,
  visualGuiLocalCaptureUnavailablePatch,
} from "./visual-gui-local-capture.mjs";

const fixturePngBase64 =
  "iVBORw0KGgoAAAANSUhEUgAAAAIAAAADCAIAAADZ5rWJAAAAFElEQVR42mP8z8AARLJgwi+Q5gIAWUMGAf2v7z8AAAAASUVORK5CYII=";

test("visual GUI local capture request detector ignores retired aliases", () => {
  assert.equal(visualGuiLocalCaptureRequested({ capture_screen: true }), true);
  assert.equal(visualGuiLocalCaptureRequested({ local_capture: true }), true);
  assert.equal(visualGuiLocalCaptureRequested({ capture_visual_gui: true }), true);
  assert.equal(visualGuiLocalCaptureRequested({ capture_provider: "fixture" }), true);
  assert.equal(visualGuiLocalCaptureRequested({ local_capture_provider: "fixture" }), true);

  for (const input of [
    { captureScreen: true },
    { localCapture: true },
    { captureVisualGui: true },
    { captureProvider: "fixture" },
    { localCaptureProvider: "fixture" },
  ]) {
    assert.equal(visualGuiLocalCaptureRequested(input), false);
  }
});

test("visual GUI local fixture capture emits canonical patch fields only", () => {
  const previous = process.env.IOI_RUNTIME_ENABLE_VISUAL_CAPTURE_FIXTURE;
  process.env.IOI_RUNTIME_ENABLE_VISUAL_CAPTURE_FIXTURE = "1";
  const captureDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-visual-capture-test-"));
  try {
    const result = captureLocalVisualGuiObservation({
      input: {
        capture_screen: true,
        capture_provider: "fixture",
        capture_fixture_png_base64: fixturePngBase64,
        capture_ax_tree: true,
        capture_fixture_ax_tree: { role: "window" },
        capture_coordinate_space_id: "screen_fixture",
        capture_app_name: "Fixture App",
        capture_window_title: "Fixture Window",
        detected_patterns: ["fixture_pattern"],
      },
      captureDir,
      toolCallId: "capture_alias_test",
    });

    assert.equal(result.status, "captured");
    assert.equal(result.receipt.schema_version, "ioi.runtime.visual-gui-local-capture.v1");
    assert.equal(result.inputPatch.coordinate_space_id, "screen_fixture");
    assert.equal(result.inputPatch.app_name, "Fixture App");
    assert.equal(result.inputPatch.window_title, "Fixture Window");
    assert.equal(result.inputPatch.viewport_width, 2);
    assert.equal(result.inputPatch.viewport_height, 3);
    assert.equal(result.inputPatch.visual_targets[0].target_ref, "target_capture_alias_test_captured_surface");
    assert.deepEqual(result.inputPatch.visual_targets[0].available_actions, ["inspect"]);
    assert.equal(result.inputPatch.visual_targets[0].bounds.coordinate_space_id, "screen_fixture");
    assert.equal(result.inputPatch.computer_use_visual_capture_receipt, result.receipt);
    for (const key of [
      "screenshotPath",
      "coordinateSpaceId",
      "detectedPatterns",
      "computerUseVisualCaptureReceipt",
      "axPath",
      "appName",
      "windowTitle",
      "viewportWidth",
      "viewportHeight",
      "visualTargets",
    ]) {
      assert.equal(Object.hasOwn(result.inputPatch, key), false);
    }
    for (const key of ["targetRef", "availableActions"]) {
      assert.equal(Object.hasOwn(result.inputPatch.visual_targets[0], key), false);
    }
    assert.equal(Object.hasOwn(result.inputPatch.visual_targets[0].bounds, "coordinateSpaceId"), false);
  } finally {
    process.env.IOI_RUNTIME_ENABLE_VISUAL_CAPTURE_FIXTURE = previous;
    fs.rmSync(captureDir, { recursive: true, force: true });
  }
});

test("visual GUI local unavailable patch emits canonical clearing fields only", () => {
  const patch = visualGuiLocalCaptureUnavailablePatch({});

  assert.deepEqual(Object.keys(patch).sort(), [
    "app_name",
    "ax_path",
    "ax_ref",
    "detected_patterns",
    "screenshot_path",
    "screenshot_ref",
    "som_path",
    "som_ref",
    "visual_targets",
    "window_title",
  ]);
  assert.deepEqual(visualGuiLocalCaptureUnavailablePatch({ screenshot_ref: "artifact_one" }), {});
  assert.notDeepEqual(visualGuiLocalCaptureUnavailablePatch({ screenshotRef: "retired" }), {});
});
