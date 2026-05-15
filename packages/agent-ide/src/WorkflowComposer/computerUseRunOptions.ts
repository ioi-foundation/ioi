import type { WorkflowProject } from "../types/graph";

export const WORKFLOW_COMPOSER_COMPUTER_USE_RUN_OPTIONS_SCHEMA_VERSION =
  "ioi.workflow.composer-computer-use-run-options.v1" as const;

export interface WorkflowComposerComputerUseRunMetadata {
  schemaVersion: typeof WORKFLOW_COMPOSER_COMPUTER_USE_RUN_OPTIONS_SCHEMA_VERSION;
  source: "react_flow_workflow";
  computerUse: true;
  computerUseLane: string;
  computerUseSessionMode: string;
  computerUseActionKind: string;
  computerUseApprovalRef?: string;
  computerUseTargetRef?: string;
  selector?: string;
  text?: string;
  cdpEndpointUrl?: string;
  cdpWebSocketUrl?: string;
  cdpTimeoutMs?: number;
  observationRetentionMode: string | null;
  failClosedWhenUnavailable: boolean;
  workflowGraphId: string | null;
  workflowNodeId: string;
  workflowNodeIds: string[];
  toolRef: string | null;
  authorityScopes: string[];
}

export interface WorkflowComposerComputerUseRunOptions {
  metadata: WorkflowComposerComputerUseRunMetadata;
}

export function workflowComposerComputerUseRunOptions(
  workflow: WorkflowProject,
): WorkflowComposerComputerUseRunOptions | null {
  const computerUseNodes = workflow.nodes
    .filter((node) => node.type === "plugin_tool")
    .map((node) => {
      const toolBinding = node.config?.logic?.toolBinding;
      const args = toolBinding?.arguments ?? {};
      return {
        node,
        toolBinding,
        args,
      };
    })
    .filter(({ args }) => args["computerUse"] === true || args["computer_use"] === true);
  const first = computerUseNodes[0];
  if (!first) return null;
  const lane =
    cleanString(first.args["computerUseLane"]) ??
    cleanString(first.args["computer_use_lane"]) ??
    "native_browser";
  const sessionMode =
    cleanString(first.args["computerUseSessionMode"]) ??
    cleanString(first.args["computer_use_session_mode"]) ??
    defaultSessionModeForLane(lane);
  const actionKind =
    cleanString(first.args["computerUseActionKind"]) ??
    cleanString(first.args["computer_use_action_kind"]) ??
    cleanString(first.args["actionKind"]) ??
    cleanString(first.args["action_kind"]) ??
    "inspect";
  const approvalRef =
    cleanString(first.args["computerUseApprovalRef"]) ??
    cleanString(first.args["computer_use_approval_ref"]) ??
    cleanString(first.args["approvalRef"]) ??
    cleanString(first.args["approval_ref"]);
  const targetRef =
    cleanString(first.args["computerUseTargetRef"]) ??
    cleanString(first.args["computer_use_target_ref"]) ??
    cleanString(first.args["targetRef"]) ??
    cleanString(first.args["target_ref"]);
  const selector = cleanString(first.args["selector"]) ?? cleanString(first.args["cssSelector"]);
  const text =
    cleanString(first.args["text"]) ??
    cleanString(first.args["inputText"]) ??
    cleanString(first.args["input_text"]);
  const cdpEndpointUrl =
    cleanString(first.args["cdpEndpointUrl"]) ??
    cleanString(first.args["cdp_endpoint_url"]) ??
    cleanString(first.args["cdpEndpoint"]) ??
    cleanString(first.args["cdp_endpoint"]);
  const cdpWebSocketUrl =
    cleanString(first.args["cdpWebSocketUrl"]) ??
    cleanString(first.args["cdp_websocket_url"]) ??
    cleanString(first.args["webSocketDebuggerUrl"]) ??
    cleanString(first.args["websocketDebuggerUrl"]);
  const cdpTimeoutMs = positiveNumber(
    first.args["cdpTimeoutMs"] ?? first.args["cdp_timeout_ms"],
  );
  return {
    metadata: {
      schemaVersion: WORKFLOW_COMPOSER_COMPUTER_USE_RUN_OPTIONS_SCHEMA_VERSION,
      source: "react_flow_workflow",
      computerUse: true,
      computerUseLane: lane,
      computerUseSessionMode: sessionMode,
      computerUseActionKind: actionKind,
      ...(approvalRef ? { computerUseApprovalRef: approvalRef } : {}),
      ...(targetRef ? { computerUseTargetRef: targetRef } : {}),
      ...(selector ? { selector } : {}),
      ...(text ? { text } : {}),
      ...(cdpEndpointUrl ? { cdpEndpointUrl } : {}),
      ...(cdpWebSocketUrl ? { cdpWebSocketUrl } : {}),
      ...(cdpTimeoutMs ? { cdpTimeoutMs } : {}),
      observationRetentionMode:
        cleanString(first.args["observationRetentionMode"]) ??
        cleanString(first.args["observation_retention_mode"]),
      failClosedWhenUnavailable:
        booleanValue(first.args["failClosedWhenUnavailable"]) ??
        booleanValue(first.args["fail_closed_when_unavailable"]) ??
        true,
      workflowGraphId: cleanString(workflow.metadata?.id),
      workflowNodeId: first.node.id,
      workflowNodeIds: computerUseNodes.map(({ node }) => node.id),
      toolRef: cleanString(first.toolBinding?.toolRef),
      authorityScopes: first.toolBinding?.capabilityScope ?? [],
    },
  };
}

export function mergeWorkflowComposerComputerUseRunOptions(
  base: Record<string, unknown>,
  computerUse: WorkflowComposerComputerUseRunOptions | null,
): Record<string, unknown> {
  if (!computerUse) return base;
  const existingMetadata = recordValue(base["metadata"]);
  return {
    ...base,
    metadata: {
      ...existingMetadata,
      ...computerUse.metadata,
    },
  };
}

function defaultSessionModeForLane(lane: string): string {
  if (lane === "visual_gui") return "visual_fallback";
  if (lane === "sandboxed_hosted") return "hosted_sandbox";
  return "owned_hermetic_browser";
}

function cleanString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function booleanValue(value: unknown): boolean | null {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value.toLowerCase() === "true") return true;
    if (value.toLowerCase() === "false") return false;
  }
  return null;
}

function positiveNumber(value: unknown): number | null {
  const numeric = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) return null;
  return numeric;
}

function recordValue(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}
