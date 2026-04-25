import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(
  new URL("./AutopilotShellContent.tsx", import.meta.url),
  "utf8",
);

assert.match(
  source,
  /<ChatCopilotView[\s\S]*seedIntent=\{controller\.chat\.seedIntent\}[\s\S]*onConsumeSeedIntent=\{controller\.chat\.consumeSeedIntent\}/,
  "the primary chat copilot surface should remain the only seed-intent consumer",
);

assert.match(
  source,
  /<ChatLeftUtilityPane[\s\S]*seedIntent=\{null\}[\s\S]*onConsumeSeedIntent=\{undefined\}/,
  "the auxiliary chat pane should not auto-submit the same seed intent a second time",
);

console.log("AutopilotShellContent.seedIntent.test.ts: ok");
