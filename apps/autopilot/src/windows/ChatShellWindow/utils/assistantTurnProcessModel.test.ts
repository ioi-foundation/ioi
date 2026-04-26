import assert from "node:assert/strict";
import {
  buildAssistantTurnProcess,
  hasMeaningfulProcess,
  redactProcessText,
  sourceIconFallbackForKind,
  testOnlySourceRefsFromSummary,
} from "./assistantTurnProcessModel";
import type { SourceSummary, ToolActivityGroupPresentation } from "../../../types";

const empty = buildAssistantTurnProcess({
  task: null,
  planSummary: null,
  runtimeModelLabel: "Local: qwen3.5:9b",
  sourceSummary: null,
  thoughtSummary: null,
  toolActivityGroup: null,
  isRunning: false,
});

assert.equal(hasMeaningfulProcess(empty), false);

const toolGroup: ToolActivityGroupPresentation = {
  key: "tool-group:1",
  label: "1 tool call",
  defaultOpen: true,
  rows: [
    {
      key: "cmd:1",
      kind: "verify",
      status: "complete",
      stepIndex: 1,
      label: "Ran npm run typecheck",
      detail: "npm run typecheck --token abcdefghijklmnopqrstuvwxyz123456",
      preview: "completed successfully",
    },
  ],
};

const withTool = buildAssistantTurnProcess({
  runtimeModelLabel: "Local: qwen3.5:9b",
  toolActivityGroup: toolGroup,
});

assert.equal(hasMeaningfulProcess(withTool), true);
assert.equal(withTool.items.length, 1);
assert.match(withTool.items[0]?.detail ?? "", /redacted/);

const invalidToolCall = buildAssistantTurnProcess({
  task: {
    id: "task-invalid-tool",
    phase: "Running",
    current_step:
      "Executed system::invalid_tool_call: ERROR_CLASS=UnexpectedState Failed to parse tool call",
  } as any,
  runtimeModelLabel: "Local: qwen3.5:9b",
  isRunning: true,
});

assert.equal(invalidToolCall.status, "failed");
assert.equal(invalidToolCall.items[0]?.label, "Tool call rejected");

const sourceSummary: SourceSummary = {
  totalSources: 1,
  sourceUrls: ["https://example.com/docs"],
  domains: [{ domain: "example.com", faviconUrl: "app://favicon/example", count: 1 }],
  searches: [],
  browses: [
    {
      url: "https://example.com/docs",
      domain: "example.com",
      title: "Example Docs",
      stepIndex: 1,
    },
  ],
};

const sources = testOnlySourceRefsFromSummary(sourceSummary);
assert.equal(sources[0]?.faviconUrl, "app://favicon/example");
assert.equal(sources[0]?.iconFallback, "globe");
assert.equal(sourceIconFallbackForKind("command"), "terminal");
assert.equal(sourceIconFallbackForKind("screenshot"), "image");
assert.equal(redactProcessText("Authorization bearer abcdefghijklmnopqrstuvwxyz123456"), "[redacted] [redacted] [redacted]");

console.log("assistantTurnProcessModel.test.ts: ok");
