import assert from "node:assert/strict";
import test from "node:test";

import { codingToolContracts, codingToolInputSummary, codingToolResultSummary } from "./coding-tools.mjs";

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
      edit_count: 3,
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
      edit_count: 0,
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

test("coding tool result summaries use canonical snake_case result fields", () => {
  assert.deepEqual(
    codingToolResultSummary("file.apply_patch", {
      path: "src/app.mjs",
      dry_run: true,
      applied: false,
      changed: true,
      edit_count: 2,
      changed_files: [{ path: "src/app.mjs" }],
      workspace_snapshot_id: "snapshot_alpha",
    }),
    {
      path: "src/app.mjs",
      dry_run: true,
      applied: false,
      changed: true,
      edit_count: 2,
      changed_file_count: 1,
      workspace_snapshot_id: "snapshot_alpha",
    },
  );
  assert.deepEqual(
    codingToolResultSummary("test.run", {
      command_id: "npm.test",
      test_status: "passed",
      exit_code: 0,
      duration_ms: 18,
      spillover_recommended: true,
    }),
    {
      command_id: "npm.test",
      test_status: "passed",
      exit_code: 0,
      duration_ms: 18,
      truncated: false,
      spillover_recommended: true,
    },
  );
  assert.deepEqual(
    codingToolResultSummary("lsp.diagnostics", {
      command_id: "typescript.check",
      resolved_command_id: "typescript.check",
      backend: "typescript.project.check",
      diagnostic_status: "findings",
      diagnostic_count: 1,
      backend_status: "available",
      fallback_used: false,
    }),
    {
      command_id: "typescript.check",
      resolved_command_id: "typescript.check",
      backend: "typescript.project.check",
      diagnostic_status: "findings",
      diagnostic_count: 1,
      backend_status: "available",
      fallback_used: false,
      truncated: false,
      spillover_recommended: false,
    },
  );
});

test("coding tool result summaries ignore retired camelCase result aliases", () => {
  assert.deepEqual(
    codingToolResultSummary("file.apply_patch", {
      path: "src/app.mjs",
      dryRun: true,
      editCount: 2,
      changedFiles: [{ path: "src/app.mjs" }],
      workspaceSnapshotId: "snapshot_retired",
    }),
    {
      path: "src/app.mjs",
      dry_run: false,
      applied: false,
      changed: false,
      edit_count: 0,
      changed_file_count: 0,
      workspace_snapshot_id: null,
    },
  );
  assert.deepEqual(
    codingToolResultSummary("lsp.diagnostics", {
      commandId: "typescript.check",
      resolvedCommandId: "typescript.check",
      diagnosticStatus: "findings",
      diagnosticCount: 1,
      backendStatus: "available",
      fallbackUsed: true,
    }),
    {
      command_id: null,
      resolved_command_id: null,
      backend: null,
      diagnostic_status: null,
      diagnostic_count: 0,
      backend_status: null,
      fallback_used: false,
      truncated: false,
      spillover_recommended: false,
    },
  );
});

test("coding tool output contracts require canonical snake_case result fields", () => {
  const contracts = Object.fromEntries(codingToolContracts().map((contract) => [contract.stable_tool_id, contract]));
  assert.ok(contracts["workspace.status"].output_schema.required.includes("changed_files"));
  assert.ok(!contracts["workspace.status"].output_schema.required.includes("changedFiles"));
  assert.ok(contracts["file.apply_patch"].output_schema.required.includes("before_hash"));
  assert.ok(!contracts["file.apply_patch"].output_schema.required.includes("beforeHash"));
  assert.ok(contracts["test.run"].output_schema.required.includes("test_status"));
  assert.ok(!contracts["test.run"].output_schema.required.includes("testStatus"));
  assert.ok(contracts["lsp.diagnostics"].output_schema.required.includes("diagnostic_status"));
  assert.ok(!contracts["lsp.diagnostics"].output_schema.required.includes("diagnosticStatus"));
});
