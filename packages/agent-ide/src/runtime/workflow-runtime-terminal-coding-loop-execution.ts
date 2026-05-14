import type { Node } from "../types/graph";
import {
  createRuntimeCodingToolControlRequestFromWorkflowNode,
  type RuntimeCodingToolControlRequest,
} from "./workflow-runtime-coding-tool-control-nodes";
import {
  WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_STEPS,
  WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_SUBFLOW_SCHEMA_VERSION,
  type WorkflowRuntimeTerminalCodingLoopStepId,
} from "./workflow-runtime-terminal-coding-loop-subflow";

export const WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_EXECUTION_SCHEMA_VERSION =
  "ioi.workflow.runtime-terminal-coding-loop-execution.v1" as const;

export interface WorkflowRuntimeTerminalCodingLoopExecutionContext {
  schemaVersion?: typeof WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_EXECUTION_SCHEMA_VERSION;
  threadId: string;
  turnId?: string | null;
  cursor?: string | null;
  lastEventId?: string | null;
  sequence?: number | null;
  toolCallId?: string | null;
  resultToolCallId?: string | null;
  artifactId?: string | null;
  runtimeTelemetrySummary?: unknown;
  receiptRefs?: string[];
  artifactRefs?: string[];
  rollbackRefs?: string[];
  policyDecisionRefs?: string[];
}

export interface WorkflowRuntimeTerminalCodingLoopStepRequestOptions {
  workflowGraphId?: string | null;
  actor?: string | null;
}

const STEP_ORDER = new Map(
  WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_STEPS.map((step, index) => [
    step.stepId,
    index,
  ]),
);

export function workflowRuntimeTerminalCodingLoopNodesInExecutionOrder<
  T extends Pick<Node, "id" | "type" | "config">,
>(nodes: readonly T[]): T[] {
  return nodes
    .filter((node) => {
      const stepId = terminalCodingLoopStepId(node);
      return stepId ? STEP_ORDER.has(stepId) : false;
    })
    .sort((left, right) => {
      const leftIndex = STEP_ORDER.get(terminalCodingLoopStepId(left)!) ?? 0;
      const rightIndex = STEP_ORDER.get(terminalCodingLoopStepId(right)!) ?? 0;
      return leftIndex - rightIndex;
    });
}

export function createRuntimeTerminalCodingLoopStepRequest(
  node: Pick<Node, "id" | "type" | "config">,
  context: WorkflowRuntimeTerminalCodingLoopExecutionContext,
  options: WorkflowRuntimeTerminalCodingLoopStepRequestOptions = {},
): RuntimeCodingToolControlRequest {
  const logic = node.config?.logic ?? {};
  const requestNode = terminalCodingLoopNodeWithResolvedArguments(node, context);
  return createRuntimeCodingToolControlRequestFromWorkflowNode(
    requestNode,
    {
      threadId: context.threadId,
      turnId: context.turnId,
      cursor: context.cursor,
      lastEventId: context.lastEventId,
      sequence: context.sequence,
      toolCallId: context.resultToolCallId ?? context.toolCallId,
      artifactId: context.artifactId,
      runtimeTelemetrySummary: context.runtimeTelemetrySummary,
    },
    {
      workflowGraphId:
        options.workflowGraphId ??
        cleanString(logic.runtimeTerminalCodingLoopWorkflowGraphId) ??
        null,
      actor:
        options.actor ??
        cleanString(logic.runtimeTerminalCodingLoopActor) ??
        "operator",
    },
  );
}

export function updateRuntimeTerminalCodingLoopExecutionContextFromToolResult(
  context: WorkflowRuntimeTerminalCodingLoopExecutionContext,
  result: unknown,
): WorkflowRuntimeTerminalCodingLoopExecutionContext {
  const resultObject = objectRecord(result);
  const event = objectRecord(valueAt(resultObject, "event"));
  const payload = objectRecord(valueAt(event, "payload_summary")) ??
    objectRecord(valueAt(event, "payload"));
  const resultSummary = objectRecord(valueAt(resultObject, "result")) ??
    objectRecord(valueAt(payload, "result_summary"));
  const toolName =
    cleanString(valueAt(resultObject, "tool_name")) ??
    cleanString(valueAt(resultObject, "toolName")) ??
    cleanString(valueAt(payload, "tool_name")) ??
    cleanString(valueAt(payload, "toolName"));
  const toolCallId =
    cleanString(valueAt(resultObject, "tool_call_id")) ??
    cleanString(valueAt(resultObject, "toolCallId")) ??
    cleanString(valueAt(event, "tool_call_id")) ??
    cleanString(valueAt(event, "toolCallId")) ??
    cleanString(valueAt(payload, "tool_call_id")) ??
    cleanString(valueAt(payload, "toolCallId")) ??
    context.toolCallId ??
    null;
  const eventId =
    cleanString(valueAt(event, "event_id")) ??
    cleanString(valueAt(event, "id")) ??
    context.lastEventId ??
    null;
  const sequence =
    finiteNumber(valueAt(event, "seq")) ??
    finiteNumber(valueAt(resultObject, "sequence")) ??
    context.sequence ??
    null;
  const eventStreamId =
    cleanString(valueAt(event, "event_stream_id")) ??
    cleanString(valueAt(event, "eventStreamId"));
  const cursor =
    cleanString(valueAt(resultObject, "cursor")) ??
    cleanString(valueAt(event, "cursor")) ??
    (eventStreamId && sequence !== null ? `${eventStreamId}:${sequence}` : null) ??
    context.cursor ??
    null;
  const outputArtifactIds = artifactIdsFromResult(resultSummary, "output");
  const artifactRefs = uniqueStrings([
    ...(context.artifactRefs ?? []),
    ...stringArray(valueAt(resultObject, "artifact_refs")),
    ...stringArray(valueAt(resultObject, "artifactRefs")),
    ...stringArray(valueAt(event, "artifact_refs")),
    ...stringArray(valueAt(event, "artifactRefs")),
    ...stringArray(valueAt(resultSummary, "artifactRefs")),
    ...artifactIdsFromResult(resultSummary),
  ]);
  const outputArtifactId =
    outputArtifactIds[0] ??
    context.artifactId ??
    artifactRefs[0] ??
    null;
  const isRetrievableProducer =
    Boolean(toolCallId) &&
    outputArtifactIds.length > 0 &&
    toolName !== "artifact.read" &&
    toolName !== "tool.retrieve_result";

  return {
    ...context,
    schemaVersion: WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_EXECUTION_SCHEMA_VERSION,
    turnId:
      cleanString(valueAt(resultObject, "turn_id")) ??
      cleanString(valueAt(resultObject, "turnId")) ??
      cleanString(valueAt(event, "turn_id")) ??
      cleanString(valueAt(event, "turnId")) ??
      context.turnId ??
      null,
    cursor,
    lastEventId: eventId,
    sequence,
    toolCallId,
    resultToolCallId: isRetrievableProducer
      ? toolCallId
      : context.resultToolCallId ?? null,
    artifactId: outputArtifactId,
    receiptRefs: uniqueStrings([
      ...(context.receiptRefs ?? []),
      ...stringArray(valueAt(resultObject, "receipt_refs")),
      ...stringArray(valueAt(resultObject, "receiptRefs")),
      ...stringArray(valueAt(event, "receipt_refs")),
      ...stringArray(valueAt(event, "receiptRefs")),
    ]),
    artifactRefs,
    rollbackRefs: uniqueStrings([
      ...(context.rollbackRefs ?? []),
      ...stringArray(valueAt(resultObject, "rollback_refs")),
      ...stringArray(valueAt(resultObject, "rollbackRefs")),
      ...stringArray(valueAt(event, "rollback_refs")),
      ...stringArray(valueAt(event, "rollbackRefs")),
    ]),
    policyDecisionRefs: uniqueStrings([
      ...(context.policyDecisionRefs ?? []),
      ...stringArray(valueAt(resultObject, "policy_decision_refs")),
      ...stringArray(valueAt(resultObject, "policyDecisionRefs")),
      ...stringArray(valueAt(event, "policy_decision_refs")),
      ...stringArray(valueAt(event, "policyDecisionRefs")),
    ]),
  };
}

function terminalCodingLoopNodeWithResolvedArguments(
  node: Pick<Node, "id" | "type" | "config">,
  context: WorkflowRuntimeTerminalCodingLoopExecutionContext,
): Pick<Node, "id" | "type" | "config"> {
  const config = node.config;
  const logic = config?.logic;
  const binding = logic?.toolBinding;
  if (!config || !logic || !binding) return node;
  const resolvedArguments = objectRecord(
    resolveTerminalCodingLoopPlaceholders(binding.arguments, context),
  ) ?? {};
  return {
    ...node,
    config: {
      ...config,
      logic: {
        ...logic,
        toolBinding: {
          ...binding,
          arguments: resolvedArguments,
        },
      },
    },
  };
}

function resolveTerminalCodingLoopPlaceholders(
  value: unknown,
  context: WorkflowRuntimeTerminalCodingLoopExecutionContext,
): unknown {
  if (typeof value === "string") {
    const replacements: Record<string, string | null | undefined> = {
      threadId: context.threadId,
      turnId: context.turnId,
      cursor: context.cursor,
      lastEventId: context.lastEventId,
      sequence:
        typeof context.sequence === "number" ? String(context.sequence) : null,
      toolCallId: context.resultToolCallId ?? context.toolCallId,
      latestToolCallId: context.toolCallId,
      artifactId: context.artifactId,
    };
    return value.replace(/\{([a-zA-Z0-9_.-]+)\}/g, (match, key) => {
      const replacement = replacements[key];
      return replacement === null || replacement === undefined
        ? match
        : String(replacement);
    });
  }
  if (Array.isArray(value)) {
    return value.map((entry) =>
      resolveTerminalCodingLoopPlaceholders(entry, context),
    );
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [
        key,
        resolveTerminalCodingLoopPlaceholders(entry, context),
      ]),
    );
  }
  return value;
}

function terminalCodingLoopStepId(
  node: Pick<Node, "config">,
): WorkflowRuntimeTerminalCodingLoopStepId | null {
  const logic = node.config?.logic;
  if (
    logic?.runtimeTerminalCodingLoopSchemaVersion !==
    WORKFLOW_RUNTIME_TERMINAL_CODING_LOOP_SUBFLOW_SCHEMA_VERSION
  ) {
    return null;
  }
  const stepId = cleanString(logic.runtimeTerminalCodingLoopStepId);
  return stepId && STEP_ORDER.has(stepId as WorkflowRuntimeTerminalCodingLoopStepId)
    ? (stepId as WorkflowRuntimeTerminalCodingLoopStepId)
    : null;
}

function valueAt(source: unknown, key: string): unknown {
  if (!source || typeof source !== "object" || Array.isArray(source)) {
    return undefined;
  }
  return (source as Record<string, unknown>)[key];
}

function objectRecord(source: unknown): Record<string, unknown> | null {
  return source && typeof source === "object" && !Array.isArray(source)
    ? (source as Record<string, unknown>)
    : null;
}

function cleanString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function finiteNumber(value: unknown): number | null {
  const parsed =
    typeof value === "number"
      ? value
      : typeof value === "string" && value.trim()
        ? Number(value)
        : null;
  return typeof parsed === "number" && Number.isFinite(parsed) ? parsed : null;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value
        .map((entry) => cleanString(entry))
        .filter((entry): entry is string => Boolean(entry))
    : [];
}

function artifactIdsFromResult(
  result: Record<string, unknown> | null,
  channel?: string,
): string[] {
  const artifacts = valueAt(result, "artifacts");
  if (!Array.isArray(artifacts)) return [];
  return artifacts
    .filter((artifact) => {
      if (!channel) return true;
      return cleanString(valueAt(artifact, "channel")) === channel;
    })
    .map((artifact) => cleanString(valueAt(artifact, "artifactId")))
    .filter((artifactId): artifactId is string => Boolean(artifactId));
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.filter((value) => value.trim()))];
}
