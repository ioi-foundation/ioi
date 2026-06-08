import assert from "node:assert/strict";
import test from "node:test";

import { codingToolInputSummary } from "./coding-tools.mjs";

test("coding tool input summaries use canonical snake_case request fields", () => {
  assert.deepEqual(
    codingToolInputSummary("file.apply_patch", {
      path: "src/app.mjs",
      dry_run: true,
      old_text: "before",
      new_text: "after",
      append_text: "tail",
      prepend_text: "head",
    }),
    {
      path: "src/app.mjs",
      dry_run: true,
      editCount: 3,
    },
  );

  assert.deepEqual(
    codingToolInputSummary("test.run", {
      command_id: "npm.test",
      paths: ["packages/runtime-daemon/src/coding-tools.mjs"],
      cwd: "packages/runtime-daemon",
      timeout_ms: 1500,
    }),
    {
      command_id: "npm.test",
      paths: ["packages/runtime-daemon/src/coding-tools.mjs"],
      cwd: "packages/runtime-daemon",
      timeout_ms: 1500,
    },
  );

  assert.deepEqual(
    codingToolInputSummary("lsp.diagnostics", {
      command_id: "typescript.check",
      path: "packages/runtime-daemon/src/coding-tools.mjs",
      timeout_ms: 1200,
    }),
    {
      command_id: "typescript.check",
      paths: ["packages/runtime-daemon/src/coding-tools.mjs"],
      cwd: ".",
      timeout_ms: 1200,
    },
  );

  assert.deepEqual(codingToolInputSummary("workspace.status", { include_ignored: true }), {
    include_ignored: true,
  });
});

test("coding tool input summaries ignore retired camelCase request aliases", () => {
  assert.deepEqual(
    codingToolInputSummary("file.apply_patch", {
      path: "src/app.mjs",
      dryRun: true,
      oldText: "before",
      newText: "after",
      appendText: "tail",
      prependText: "head",
    }),
    {
      path: "src/app.mjs",
      dry_run: false,
      editCount: 0,
    },
  );

  assert.deepEqual(
    codingToolInputSummary("test.run", {
      commandId: "npm.test",
      timeoutMs: 1500,
    }),
    {
      command_id: "node.test",
      paths: [],
      cwd: ".",
      timeout_ms: null,
    },
  );

  assert.deepEqual(
    codingToolInputSummary("lsp.diagnostics", {
      commandId: "typescript.check",
      timeoutMs: 1200,
    }),
    {
      command_id: "auto",
      paths: [],
      cwd: ".",
      timeout_ms: null,
    },
  );

  assert.deepEqual(codingToolInputSummary("workspace.status", { includeIgnored: true }), {
    include_ignored: false,
  });
});
