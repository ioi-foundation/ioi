#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-chat-responsibility-negative-matrix-proof.mjs <output-path>");
}

const { buildWorkflowChatResponsibilityContract } = await import(
  "../../packages/agent-ide/src/runtime/workflow-chat-responsibility-contract.ts"
);

const contract = buildWorkflowChatResponsibilityContract({
  turns: [
    {
      mode: "ask",
      routeId: "route.local-first",
      prompt: "thanks, can you explain the issue plainly?",
      responseText: "The issue is the Agent harness must emit a visible reply before completion.",
      visibleAssistantText: "The issue is the Agent harness must emit a visible reply before completion.",
      latencyMs: 700,
      receiptId: "receipt:stage58:ask-ok",
      toolSequence: [],
    },
    {
      mode: "ask",
      routeId: "route.local-first",
      prompt: "hiya bot",
      responseText: JSON.stringify({ name: "chat__reply", arguments: { message: "Hello" } }),
      visibleAssistantText: null,
      latencyMs: 900,
      receiptId: "receipt:stage58:ask-tool-leak",
      toolSequence: [],
    },
    {
      mode: "agent",
      routeId: "route.local-first",
      prompt: "they can only ignore it for so long",
      responseText: JSON.stringify({ name: "agent__complete", arguments: { result: "done" } }),
      visibleAssistantText: null,
      latencyMs: 1200,
      receiptId: "receipt:stage58:agent-complete-only",
      toolSequence: ["agent__complete"],
    },
    {
      mode: "agent",
      routeId: "route.local-first",
      prompt: "thanks, summarize the fix",
      responseText: JSON.stringify({ name: "chat__reply", arguments: { message: "Fixed." } }),
      visibleAssistantText: "Fixed.",
      latencyMs: 35_001,
      receiptId: "receipt:stage58:agent-slow",
      toolSequence: ["chat__reply"],
    },
  ],
});

const rows = new Map(contract.rows.map((row) => [row.receiptId, row]));
assert.equal(contract.schemaVersion, "ioi.workflow.chat-responsibility-contract.v1");
assert.equal(contract.status, "blocked");
assert.equal(contract.directChatCount, 2);
assert.equal(contract.agentHarnessCount, 2);
assert.equal(contract.conversationalTurnCount, 4);
assert.equal(contract.directToolLeakCount, 1);
assert.equal(contract.missingAgentReplyCount, 1);
assert.equal(contract.agentCompleteWithoutReplyCount, 1);
assert.equal(contract.slowTurnCount, 1);
assert.equal(rows.get("receipt:stage58:ask-ok")?.status, "ready");
assert.equal(rows.get("receipt:stage58:ask-tool-leak")?.issue, "ask_mode_returned_agent_tool_call");
assert.equal(rows.get("receipt:stage58:agent-complete-only")?.issue, "agent_mode_missing_chat_reply");
assert.equal(rows.get("receipt:stage58:agent-complete-only")?.agentCompleteWithoutReply, true);
assert.equal(rows.get("receipt:stage58:agent-slow")?.issue, "turn_exceeded_30s_threshold");
assert.equal(rows.get("receipt:stage58:agent-slow")?.chatReplyCalled, true);

const proof = {
  schemaVersion: "ioi.autopilot.stage58.chat-responsibility-negative-matrix-proof.v1",
  passed: true,
  generatedAt: new Date().toISOString(),
  checks: {
    askToolLeakBlocked: contract.directToolLeakCount === 1,
    agentCompleteWithoutReplyBlocked: contract.agentCompleteWithoutReplyCount === 1,
    missingAgentReplyBlocked: contract.missingAgentReplyCount === 1,
    slowConversationalTurnBlocked: contract.slowTurnCount === 1,
    healthyAskTurnStillReady: rows.get("receipt:stage58:ask-ok")?.status === "ready",
  },
  contract,
};

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
