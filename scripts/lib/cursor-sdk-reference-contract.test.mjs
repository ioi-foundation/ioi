import assert from "node:assert/strict";
import test from "node:test";

import {
  REQUIRED_CURSOR_CAPABILITIES,
  REQUIRED_CURSOR_REFERENCE_MODULES,
  assertReferenceInventoryComplete,
} from "./cursor-sdk-reference-contract.mjs";

test("Cursor SDK reference contract keeps every audited module and capability classified", () => {
  assert.ok(REQUIRED_CURSOR_REFERENCE_MODULES.includes("dist/esm/agent.d.ts"));
  assert.ok(REQUIRED_CURSOR_REFERENCE_MODULES.includes("dist/esm/run.d.ts"));
  assert.ok(REQUIRED_CURSOR_CAPABILITIES.includes("Agent.create"));
  assert.ok(REQUIRED_CURSOR_CAPABILITIES.includes("Run.stream"));
  assert.doesNotThrow(() =>
    assertReferenceInventoryComplete({
      capabilities: REQUIRED_CURSOR_CAPABILITIES,
      modules: Object.fromEntries(
        REQUIRED_CURSOR_REFERENCE_MODULES.map((modulePath) => [
          modulePath,
          { missing: false, exports: [], interfaces: [], classes: [], methods: [] },
        ]),
      ),
    }),
  );
});
