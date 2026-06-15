#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";
import { bootstrapNativeRuntimeModelRoute } from "./autopilot-runtime-agent-service-inference.mjs";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-chat-responsibility-contract-proof.mjs <output-path>");
}

const { buildWorkflowChatResponsibilityContract } = await import(
  "../../packages/agent-ide/src/runtime/workflow-chat-responsibility-contract.ts"
);

async function createToken(endpoint) {
  const response = await fetch(`${endpoint}/api/v1/tokens`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      label: "stage31-chat-responsibility",
      allowed: [
        "model.chat:*",
        "route.use:*",
        "model.import:*",
        "model.mount:*",
        "model.load:*",
        "route.write:*",
      ],
    }),
  });
  const body = await response.json();
  assert.ok(response.ok, `${response.status} ${JSON.stringify(body)}`);
  return body;
}

async function chatCompletion(endpoint, token, body) {
  const started = performance.now();
  const response = await fetch(`${endpoint}/v1/chat/completions`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body),
  });
  const json = await response.json();
  assert.ok(response.ok, `${response.status} ${JSON.stringify(json)}`);
  return {
    latencyMs: Math.round(performance.now() - started),
    response: json,
    content: json.choices?.[0]?.message?.content ?? "",
    routeId: json.route_id ?? null,
    receiptId: json.receipt_id ?? null,
  };
}

function parseTool(content) {
  const parsed = JSON.parse(content);
  return { name: parsed.name, arguments: parsed.arguments ?? {} };
}

const repoRoot = process.cwd();
const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage31-workspace-"));
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage31-state-"));
let daemon = null;

try {
  daemon = await startRuntimeDaemonService({ cwd, stateDir });
  const grant = await createToken(daemon.endpoint);
  const route = await bootstrapNativeRuntimeModelRoute({
    repoRoot,
    daemonEndpoint: daemon.endpoint,
    token: grant.token,
    workspaceDir: cwd,
  });

  const prompt = "they can only ignore it for so long";
  const direct = await chatCompletion(daemon.endpoint, grant.token, {
    model: "auto",
    route_id: route.routeId,
    messages: [{ role: "user", content: prompt }],
    stream: false,
  });
  assert.match(direct.content, /evidence/i);
  assert.doesNotMatch(direct.content, /chat__reply|agent__complete/);
  assert.ok(direct.latencyMs < 30_000);

  const agentSystem = [
    "[AVAILABLE TOOLS]",
    "chat__reply(message: string)",
    "agent__complete(result: string)",
    "Output EXACTLY ONE valid JSON tool call.",
  ].join("\n");
  const agentReply = await chatCompletion(daemon.endpoint, grant.token, {
    model: "auto",
    route_id: route.routeId,
    messages: [
      { role: "system", content: agentSystem },
      { role: "user", content: prompt },
    ],
    stream: false,
  });
  const replyTool = parseTool(agentReply.content);
  assert.equal(replyTool.name, "chat__reply");
  assert.match(replyTool.arguments.message, /evidence/i);

  const agentComplete = await chatCompletion(daemon.endpoint, grant.token, {
    model: "auto",
    route_id: route.routeId,
    messages: [
      { role: "system", content: agentSystem },
      { role: "user", content: prompt },
      { role: "assistant", content: agentReply.content },
      { role: "tool", content: "Tool Output (chat__reply): visible assistant message delivered" },
    ],
    stream: false,
  });
  const completeTool = parseTool(agentComplete.content);
  assert.equal(completeTool.name, "agent__complete");

  const contract = buildWorkflowChatResponsibilityContract({
    turns: [
      {
        mode: "ask",
        routeId: direct.routeId,
        prompt,
        responseText: direct.content,
        visibleAssistantText: direct.content,
        latencyMs: direct.latencyMs,
        receiptId: direct.receiptId,
        toolSequence: [],
      },
      {
        mode: "agent",
        routeId: agentReply.routeId,
        prompt,
        responseText: agentReply.content,
        visibleAssistantText: replyTool.arguments.message,
        latencyMs: agentReply.latencyMs + agentComplete.latencyMs,
        receiptId: agentReply.receiptId,
        toolSequence: [replyTool.name, completeTool.name],
      },
    ],
  });
  assert.equal(contract.status, "ready");
  assert.equal(contract.directToolLeakCount, 0);
  assert.equal(contract.missingAgentReplyCount, 0);
  assert.equal(contract.agentCompleteWithoutReplyCount, 0);
  assert.equal(contract.slowTurnCount, 0);
  assert.equal(contract.conversationalTurnCount, 2);

  const proof = {
    schemaVersion: "ioi.autopilot.stage31.chat-responsibility-contract-proof.v1",
    passed: true,
    cwd,
    stateDir,
    endpoint: daemon.endpoint,
    route,
    prompt,
    checks: {
      askDirectModelAnswerVisible: direct.content.includes("evidence"),
      askDidNotEmitToolCall: !/chat__reply|agent__complete/.test(direct.content),
      agentCalledChatReplyBeforeComplete: replyTool.name === "chat__reply" && completeTool.name === "agent__complete",
      conversationalNotJustGreetingCovered: prompt === "they can only ignore it for so long",
      directUnder30s: direct.latencyMs < 30_000,
      agentUnder30s: agentReply.latencyMs + agentComplete.latencyMs < 30_000,
      contractReady: contract.status === "ready",
    },
    direct,
    agent: {
      reply: agentReply,
      complete: agentComplete,
      toolSequence: [replyTool.name, completeTool.name],
      visibleAssistantText: replyTool.arguments.message,
    },
    contract,
  };

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
} finally {
  if (daemon) await daemon.close();
}
