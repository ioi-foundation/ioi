#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error("usage: workflow-model-capability-selector-proof.mjs <output-path>");
}

const { buildWorkflowModelCapabilitySelector } = await import(
  "../../packages/agent-ide/src/runtime/workflow-model-capability-selector.ts"
);

async function fetchJson(url, options) {
  const response = await fetch(url, {
    headers: { "content-type": "application/json" },
    ...options,
  });
  const body = await response.json();
  assert.ok(response.ok, `${response.status} ${response.statusText} for ${url}: ${JSON.stringify(body)}`);
  return body;
}

const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage25-workspace-"));
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-stage25-state-"));
const daemon = await startRuntimeDaemonService({ cwd, stateDir });

try {
  const capabilities = await fetchJson(`${daemon.endpoint}/api/v1/model-capabilities`);
  assert.ok(capabilities.some((capability) => capability.routeId === "route.local-first"));
  assert.ok(capabilities.some((capability) => capability.routeId === "route.native-local"));

  const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      goal: "Prove chat and agent model selectors stay separate while sharing reasoning-effort controls.",
      options: {
        local: { cwd },
        model: { id: "auto", routeId: "route.native-local", reasoningEffort: "low" },
      },
    }),
  });
  assert.equal(thread.model_route_id, "route.native-local");

  const thinkingOff = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/thinking`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      workflowGraphId: "workflow.react-flow.model-capability-selector",
      workflowNodeId: "runtime.model-selector.thinking-off",
      reasoningEffort: "none",
    }),
  });
  assert.equal(thinkingOff.reasoning_effort, "none");

  const thinkingHigh = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/thinking`, {
    method: "POST",
    body: JSON.stringify({
      source: "react_flow",
      workflowGraphId: "workflow.react-flow.model-capability-selector",
      workflowNodeId: "runtime.model-selector.thinking-high",
      reasoningEffort: "high",
    }),
  });
  assert.equal(thinkingHigh.reasoning_effort, "high");
  assert.equal(thinkingHigh.runtime_controls.model.reasoningEffort, "high");

  const selector = buildWorkflowModelCapabilitySelector({
    capabilities,
    chatRouteId: "route.local-first",
    agentRouteId: thinkingHigh.model_route_id,
    currentReasoningEffort: thinkingHigh.reasoning_effort,
  });
  const chatRow = selector.rows.find((row) => row.rowKind === "chat_direct");
  const agentRow = selector.rows.find((row) => row.rowKind === "agent_harness");

  assert.equal(selector.status, "ready");
  assert.ok(chatRow);
  assert.ok(agentRow);
  assert.equal(chatRow.responsibility, "direct_model_answer");
  assert.equal(agentRow.responsibility, "default_agent_harness");
  assert.equal(chatRow.routeId, "route.local-first");
  assert.equal(agentRow.routeId, "route.native-local");
  assert.equal(chatRow.reasoningSelectorOwner, "chat");
  assert.equal(agentRow.reasoningSelectorOwner, "agent");
  assert.ok(chatRow.reasoningOptions.includes("none"));
  assert.ok(agentRow.reasoningOptions.includes("high"));
  assert.equal(agentRow.selectedReasoningEffort, "high");
  assert.equal(chatRow.receiptRequired, true);
  assert.equal(agentRow.receiptRequired, true);

  const proof = {
    schemaVersion: "ioi.autopilot.stage25.model-capability-selector-proof.v1",
    passed: true,
    cwd,
    stateDir,
    endpoint: daemon.endpoint,
    threadId: thread.thread_id,
    thinkingEventIds: [thinkingOff.event.event_id, thinkingHigh.event.event_id],
    checks: {
      localFirstCapabilityDetected: Boolean(chatRow),
      nativeLocalCapabilityDetected: Boolean(agentRow),
      chatAndAgentResponsibilitiesSeparate:
        chatRow.responsibility === "direct_model_answer" &&
        agentRow.responsibility === "default_agent_harness",
      reasoningCanToggleOff: thinkingOff.reasoning_effort === "none",
      reasoningCanToggleHigh: thinkingHigh.reasoning_effort === "high",
      selectorReady: selector.status === "ready",
      selectorsHaveReceiptContracts: selector.rows.every((row) => row.receiptRequired),
    },
    selector,
    controls: {
      thinkingOff: {
        reasoningEffort: thinkingOff.reasoning_effort,
        eventId: thinkingOff.event.event_id,
      },
      thinkingHigh: {
        modelRouteId: thinkingHigh.model_route_id,
        selectedModel: thinkingHigh.selected_model,
        reasoningEffort: thinkingHigh.reasoning_effort,
        eventId: thinkingHigh.event.event_id,
      },
    },
  };

  fs.mkdirSync(path.dirname(outputPath), { recursive: true });
  fs.writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`);
} finally {
  await daemon.close();
}
