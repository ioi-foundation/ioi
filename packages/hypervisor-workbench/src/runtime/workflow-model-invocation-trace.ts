import type { WorkflowProject, WorkflowRunResult } from "../types/graph";
import { workflowNodeName } from "./workflow-rail-model";

export type WorkflowModelInvocationTraceStep = {
  phase: string;
  summary: string;
  detail: string;
};

export type WorkflowModelInvocationTraceView = {
  nodeId: string;
  nodeName: string;
  mode: string;
  modelRef: string;
  modelId: string;
  promptHash: string;
  responseHash: string;
  promptUser: string;
  trace: WorkflowModelInvocationTraceStep[];
};

function workflowRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function workflowString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

export function workflowModelInvocationTraces(
  result: WorkflowRunResult | null,
  workflow: WorkflowProject,
): WorkflowModelInvocationTraceView[] {
  if (!result) return [];
  return result.nodeRuns.flatMap((nodeRun) => {
    const output = workflowRecord(nodeRun.output);
    const invocation = workflowRecord(output?.modelInvocation);
    if (!invocation) return [];
    const prompt = workflowRecord(invocation.prompt);
    const promptUser =
      workflowString(prompt?.user) ?? "Prompt payload captured in raw state.";
    const trace = Array.isArray(invocation.trace)
      ? invocation.trace.flatMap((step): WorkflowModelInvocationTraceStep[] => {
          const item = workflowRecord(step);
          if (!item) return [];
          const phase = workflowString(item.phase) ?? "step";
          const summary =
            workflowString(item.summary) ?? "Recorded runtime step.";
          const detail =
            workflowString(item.responseHash) ??
            workflowString(item.promptHash) ??
            (typeof item.latencyMs === "number" ? `${item.latencyMs} ms` : "");
          return [{ phase, summary, detail }];
        })
      : [];
    return [
      {
        nodeId: nodeRun.nodeId,
        nodeName: workflowNodeName(workflow, nodeRun.nodeId),
        mode: workflowString(invocation.mode) ?? "model",
        modelRef: workflowString(invocation.modelRef) ?? "model",
        modelId: workflowString(invocation.modelId) ?? "unmounted",
        promptHash:
          workflowString(invocation.promptHash) ?? "prompt hash pending",
        responseHash:
          workflowString(invocation.responseHash) ?? "response hash pending",
        promptUser,
        trace,
      },
    ];
  });
}

export function workflowModelInvocationTraceSearchText(
  traces: readonly WorkflowModelInvocationTraceView[],
): string {
  return traces
    .flatMap((trace) => [
      trace.nodeId,
      trace.nodeName,
      trace.mode,
      trace.modelRef,
      trace.modelId,
      trace.promptHash,
      trace.responseHash,
      trace.promptUser,
      ...trace.trace.flatMap((step) => [step.phase, step.summary, step.detail]),
    ])
    .join(" ")
    .toLowerCase();
}
