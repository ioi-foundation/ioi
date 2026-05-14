#!/usr/bin/env node
import { writeFileSync } from "node:fs";

import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { WorkflowBottomShelf } from "../../packages/agent-ide/src/features/Workflows/WorkflowBottomShelf.tsx";

const outputPath = process.argv[2];
if (!outputPath) {
  throw new Error(
    "usage: workflow-model-invocation-trace-gui-probe.mjs <output-path>",
  );
}

const prompt = "what's the latest sports news?";
const response = "Mounted model echo: latest sports news is flowing.";
const workflow = {
  metadata: {
    id: "workflow.model-invocation-trace-proof",
    name: "Model invocation trace proof",
    slug: "model-invocation-trace-proof",
    workflowKind: "agent",
    executionMode: "manual",
  },
  nodes: [
    {
      id: "agent-step.model",
      type: "model_call",
      name: "Agent Step",
      x: 120,
      y: 120,
      config: {
        logic: {
          modelRef: "reasoning",
          modelBinding: {
            modelId: "demo-mounted-model",
          },
        },
      },
    },
  ],
  edges: [],
};
const summary = {
  id: "run-model-invocation-trace-proof",
  threadId: "thread-model-invocation-trace-proof",
  status: "passed",
  startedAtMs: 1_800_000,
  finishedAtMs: 1_801_250,
  nodeCount: 1,
  checkpointCount: 1,
  summary: "Agent Step completed through mounted model runtime.",
};
const lastRunResult = {
  summary,
  thread: {
    id: "thread-model-invocation-trace-proof",
    workflowPath:
      ".agents/workflows/model-invocation-trace-proof.workflow.json",
    status: "passed",
    createdAtMs: 1_800_000,
    input: { prompt },
  },
  finalState: {
    threadId: "thread-model-invocation-trace-proof",
    checkpointId: "checkpoint-model-invocation-trace-proof",
    runId: summary.id,
    stepIndex: 1,
    values: {
      "agent-step.model": response,
    },
    nodeOutputs: {},
    completedNodeIds: ["agent-step.model"],
    blockedNodeIds: [],
    interruptedNodeIds: [],
    activeNodeIds: [],
    branchDecisions: {},
    pendingWrites: [],
  },
  nodeRuns: [
    {
      nodeId: "agent-step.model",
      nodeType: "model_call",
      status: "success",
      startedAtMs: 1_800_050,
      finishedAtMs: 1_801_000,
      attempt: 1,
      input: { prompt },
      output: {
        response,
        modelInvocation: {
          mode: "live_mounted_model",
          modelRef: "reasoning",
          modelId: "demo-mounted-model",
          modelHash: "sha256:demo",
          bindingSource: "global.modelBindings.reasoning",
          promptHash: "sha256:prompt-proof",
          responseHash: "sha256:response-proof",
          prompt: {
            user: prompt,
            messages: [{ role: "user", content: prompt }],
          },
          trace: [
            {
              phase: "input",
              summary: "Collected upstream workflow input and typed attachments.",
            },
            {
              phase: "binding",
              summary: "Resolved the configured model binding for this Agent Step.",
            },
            {
              phase: "prompt",
              summary:
                "Assembled the canonical prompt envelope for the mounted model runtime.",
              promptHash: "sha256:prompt-proof",
            },
            {
              phase: "model",
              summary:
                "Invoked the mounted model runtime and captured the response fingerprint.",
              responseHash: "sha256:response-proof",
              latencyMs: 950,
            },
          ],
        },
      },
    },
  ],
  checkpoints: [],
  events: [
    {
      id: "event-model-invocation-succeeded",
      runId: summary.id,
      threadId: summary.threadId,
      sequence: 1,
      kind: "model_invocation_succeeded",
      createdAtMs: 1_801_000,
      nodeId: "agent-step.model",
      status: "success",
      message: "Model invocation completed.",
    },
  ],
  verificationEvidence: [],
  completionRequirements: [],
};

const html = renderToStaticMarkup(
  React.createElement(WorkflowBottomShelf, {
    panel: "run_output",
    selectedNode: null,
    selectedNodeRun: null,
    tests: [],
    proposals: [],
    testResult: null,
    validationResult: null,
    runs: [summary],
    lastRunResult,
    runDetailLoading: false,
    compareRunResult: null,
    workflow,
    functionDryRunResult: null,
    dogfoodRun: null,
    fixtures: [],
    runEvents: lastRunResult.events,
    checkpoints: [],
    logs: [],
    onCaptureFixture: () => {},
    onPinFixture: () => {},
    onDryRunFixture: () => {},
    onResumeRun: () => {},
    onInspectNode: () => {},
  }),
);

const traceStepCount = (html.match(/workflow-model-invocation-trace-step/g) ?? [])
  .length;
const checks = {
  bottomShelfRendered: html.includes('data-testid="workflow-run-detail"'),
  traceSectionRendered: html.includes(
    'data-testid="workflow-model-invocation-trace"',
  ),
  promptVisible: html.includes("latest sports news"),
  mountedModeVisible: html.includes("live_mounted_model"),
  bindingVisible: html.includes("reasoning") && html.includes("demo-mounted-model"),
  hashesVisible:
    html.includes("sha256:prompt-proof") && html.includes("sha256:response-proof"),
  tracePhasesVisible:
    html.includes(">input<") &&
    html.includes(">binding<") &&
    html.includes(">prompt<") &&
    html.includes(">model<"),
  traceStepsRendered: traceStepCount === 4,
};

const proof = {
  schemaVersion: "workflow.model-invocation-trace.gui-proof.v1",
  scenario: "workflow_model_invocation_trace_visible_prompt_pipeline",
  passed: Object.values(checks).every(Boolean),
  prompt,
  expectedEventKind: "model_invocation_succeeded",
  traceStepCount,
  checks,
  sourceRefs: [
    "packages/agent-ide/src/features/Workflows/WorkflowBottomShelf.tsx",
    "packages/agent-ide/src/runtime/workflow-rail-model.ts",
    "packages/agent-ide/src/types/graph.ts",
  ],
};

writeFileSync(outputPath, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
