import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const canvasSource = fs.readFileSync(
  new URL("./Canvas.tsx", import.meta.url),
  "utf8",
);

test("workflow canvas fit view can zoom out far enough for harness-scale graphs", () => {
  assert.match(
    canvasSource,
    /WORKFLOW_CANVAS_MIN_ZOOM\s*=\s*0\.05/,
    "workflow canvas should allow fit-view below React Flow's default zoom floor",
  );
  assert.match(
    canvasSource,
    /fitViewOptions=\{WORKFLOW_CANVAS_FIT_VIEW_OPTIONS\}/,
    "initial fit-view should use the workflow canvas fit options",
  );
  assert.match(
    canvasSource,
    /minZoom=\{WORKFLOW_CANVAS_MIN_ZOOM\}/,
    "manual Fit controls should inherit the same lower zoom floor",
  );
});
