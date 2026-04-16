import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(
  new URL("./StudioWindowMainContent.tsx", import.meta.url),
  "utf8",
);

assert.match(
  source,
  /<StudioCopilotView[\s\S]*seedIntent=\{controller\.chat\.seedIntent\}[\s\S]*onConsumeSeedIntent=\{controller\.chat\.consumeSeedIntent\}/,
  "the primary Studio copilot surface should remain the only seed-intent consumer",
);

assert.match(
  source,
  /<StudioLeftUtilityPane[\s\S]*seedIntent=\{null\}[\s\S]*onConsumeSeedIntent=\{undefined\}/,
  "the auxiliary chat pane should not auto-submit the same seed intent a second time",
);

console.log("StudioWindowMainContent.seedIntent.test.ts: ok");
