import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const controllerSource = fs.readFileSync(
  new URL("./controller.tsx", import.meta.url),
  "utf8",
);
const viewSource = fs.readFileSync(
  new URL("./view.tsx", import.meta.url),
  "utf8",
);
const composerShellCss = fs.readFileSync(
  new URL("./styles/composer-shell.css", import.meta.url),
  "utf8",
);

test("harness teaching view exposes an obvious collapse path after expanding groups", () => {
  assert.match(
    viewSource,
    /useState\(false\)/,
    "topology details should default collapsed so the graph remains the primary surface",
  );
  assert.match(
    viewSource,
    /data-topology-legend=\{/,
    "the harness teaching view should expose collapsed versus expanded state",
  );
  assert.match(
    viewSource,
    /workflow-harness-teaching-toggle-legend/,
    "group chips should be behind an explicit topology disclosure",
  );
  assert.match(
    controllerSource,
    /handleToggleHarnessGroup,/,
    "the view model should expose per-group collapse/expand toggles",
  );
  assert.match(
    viewSource,
    /workflow-harness-teaching-collapse-expanded/,
    "expanded harness groups should show an explicit back-to-overview action",
  );
  assert.match(
    viewSource,
    /Back to overview/,
    "the collapse action should use product-facing language",
  );
  assert.match(
    viewSource,
    /aria-pressed=\{!group\.collapsed\}/,
    "group chips should expose pressed state when expanded",
  );
  assert.match(
    viewSource,
    /handleToggleHarnessGroup\(String\(group\.groupId\)\)/,
    "group chips should toggle the selected harness group",
  );
  assert.match(
    composerShellCss,
    /workflow-harness-teaching-group-button\[aria-pressed="true"\]/,
    "expanded group chips should have a visible selected state",
  );
});

test("workflow canvas legend is hidden behind an explicit toggle", () => {
  assert.match(
    viewSource,
    /const \[canvasLegendOpen, setCanvasLegendOpen\] = useState\(false\);/,
    "node family legend should default collapsed",
  );
  assert.match(
    viewSource,
    /workflow-canvas-legend-toggle/,
    "the canvas should provide a compact legend disclosure",
  );
  assert.match(
    viewSource,
    /canvasLegendOpen \? \(\s*<div className="workflow-legend">/s,
    "the large node family legend should render only after the user opens it",
  );
});
