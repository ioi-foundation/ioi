import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createStudioToolResponseProjection } = require("./tool-response-projection.js");

function createProjection() {
  return createStudioToolResponseProjection({
    normalizeReceiptRefs: (...sources) => sources.flatMap((source) => {
      if (Array.isArray(source?.receiptRefs)) return source.receiptRefs;
      if (Array.isArray(source?.receipt_refs)) return source.receipt_refs;
      return [];
    }),
  });
}

test("tool response projection formats strings, objects, and bounded previews", () => {
  const { safeJsonPreview } = createProjection();

  assert.equal(safeJsonPreview(null), "");
  assert.equal(safeJsonPreview("plain text"), "plain text");
  assert.equal(safeJsonPreview({ status: "ok" }), '{\n  "status": "ok"\n}');
  assert.equal(safeJsonPreview("abcdef", 4), "abcd…");
});

test("tool response projection preserves top-level command aliases", () => {
  const { commandOutputFromToolResponse } = createProjection();

  assert.deepEqual(commandOutputFromToolResponse("shell.run", {
    tool_call_id: "tool-call-1",
    status: "completed",
    receiptRefs: ["receipt-response"],
    result: {
      command: "npm test",
      stdout: "ok",
      stderr: "",
      exit_code: 0,
      duration_ms: 25,
      receipt_refs: ["receipt-result"],
    },
  }), {
    id: "tool-call-1",
    toolId: "shell.run",
    label: "npm test",
    status: "completed",
    stdout: "ok",
    stderr: "",
    exitCode: 0,
    durationMs: 25,
    receiptRefs: ["receipt-response", "receipt-result"],
  });
});

test("tool response projection falls back to nested command output and failed exit code", () => {
  const { commandOutputFromToolResponse } = createProjection();

  const command = commandOutputFromToolResponse("lsp.diagnostics", {
    status: "failed",
    result: {
      result: {
        commandId: "node.check",
        diagnostics: [{ file: "src/app.js", message: "Syntax error" }],
        error: { message: "node --check failed" },
      },
    },
  });

  assert.match(command.id, /^lsp\.diagnostics\./);
  assert.equal(command.label, "node.check");
  assert.match(command.stdout, /Syntax error/);
  assert.equal(command.stderr, "node --check failed");
  assert.equal(command.exitCode, 1);
  assert.equal(command.durationMs, null);
});
