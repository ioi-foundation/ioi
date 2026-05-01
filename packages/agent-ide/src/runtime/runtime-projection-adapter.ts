import type {
  WorkflowConnectionClass,
  WorkflowNodeKind,
  WorkflowPortDefinition,
} from "../types/graph";
import {
  AGENT_ACTION_KINDS,
  AGENT_ACTION_COMPLETION_VERIFICATION_KINDS,
  AGENT_ACTION_ENTRY_KINDS,
  AGENT_ACTION_TERMINAL_KINDS,
} from "./generated/action-schema";

export type AgentExecutionSurface = "chat" | "workflow" | "harness" | "gui" | "unknown";

export type AgentActionKind = (typeof AGENT_ACTION_KINDS)[number];

export interface AgentActionBindingRef {
  bindingType: string;
  reference?: string;
  mockBinding: boolean;
  sideEffectClass: string;
  requiresApproval: boolean;
}

export interface AgentActionPolicy {
  privilegedActions: string[];
  requiresApproval: boolean;
  sandboxPermissions: string[];
}

export interface AgentActionFrame {
  id: string;
  surface: AgentExecutionSurface;
  kind: AgentActionKind;
  label: string;
  binding?: AgentActionBindingRef;
  policy: AgentActionPolicy;
  metadata: Record<string, unknown>;
}

export interface AgentActionValidationIssue {
  actionId?: string;
  code: string;
  message: string;
}

export function actionKindForWorkflowNodeType(nodeType: string): AgentActionKind {
  switch (nodeType) {
    case "source":
      return "source_input";
    case "trigger":
      return "trigger";
    case "task_state":
      return "task_state";
    case "uncertainty_gate":
      return "uncertainty_gate";
    case "probe":
      return "probe";
    case "budget_gate":
      return "budget_gate";
    case "capability_sequence":
      return "capability_sequence";
    case "function":
      return "function";
    case "model_binding":
      return "model_binding";
    case "model_call":
      return "model_call";
    case "parser":
      return "parser";
    case "adapter":
      return "adapter_connector";
    case "plugin_tool":
      return "plugin_tool";
    case "dry_run":
      return "dry_run";
    case "state":
      return "state";
    case "decision":
      return "decision";
    case "loop":
      return "loop";
    case "barrier":
      return "barrier";
    case "subgraph":
      return "subgraph";
    case "human_gate":
      return "human_gate";
    case "semantic_impact":
      return "semantic_impact";
    case "postcondition_synthesis":
      return "postcondition_synthesis";
    case "verifier":
      return "verifier";
    case "drift_detector":
      return "drift_detector";
    case "quality_ledger":
      return "quality_ledger";
    case "handoff":
      return "handoff";
    case "gui_harness_validation":
      return "gui_harness_validation";
    case "output":
      return "output";
    case "test_assertion":
      return "test_assertion";
    case "proposal":
      return "proposal";
    default:
      return "unknown";
  }
}

export function workflowNodeTypeForActionKind(kind: AgentActionKind): string {
  switch (kind) {
    case "source_input":
      return "source";
    case "trigger":
      return "trigger";
    case "adapter_connector":
      return "adapter";
    case "output":
      return "output";
    case "task_state":
    case "uncertainty_gate":
    case "probe":
    case "budget_gate":
    case "capability_sequence":
    case "dry_run":
    case "semantic_impact":
    case "postcondition_synthesis":
    case "verifier":
    case "drift_detector":
    case "quality_ledger":
    case "handoff":
    case "gui_harness_validation":
      return kind;
    default:
      return kind;
  }
}

export function actionKindIsEntry(kind: AgentActionKind): boolean {
  return (AGENT_ACTION_ENTRY_KINDS as readonly AgentActionKind[]).includes(kind);
}

export function actionKindIsTerminal(kind: AgentActionKind): boolean {
  return (AGENT_ACTION_TERMINAL_KINDS as readonly AgentActionKind[]).includes(kind);
}

export function actionKindRequiresCompletionVerification(kind: AgentActionKind): boolean {
  return (AGENT_ACTION_COMPLETION_VERIFICATION_KINDS as readonly AgentActionKind[]).includes(kind);
}

export function validateActionEdge(
  sourceId: string,
  sourceKind: AgentActionKind,
  targetId: string,
  targetKind: AgentActionKind,
  sourcePort?: WorkflowPortDefinition | null,
  targetPort?: WorkflowPortDefinition | null,
): AgentActionValidationIssue | null {
  if (sourceId === targetId) {
    return {
      actionId: sourceId,
      code: "self_edge",
      message: "A workflow node cannot connect to itself.",
    };
  }
  if (actionKindIsEntry(targetKind)) {
    return {
      actionId: targetId,
      code: "invalid_source_input_edge",
      message: "Source/Input nodes are workflow entry points and cannot receive incoming edges.",
    };
  }
  if (actionKindIsTerminal(sourceKind)) {
    return {
      actionId: sourceId,
      code: "invalid_output_edge",
      message: "Output nodes are terminal workflow products and cannot send outgoing edges.",
    };
  }
  const portIssue = validateWorkflowConnection(sourceKind, targetKind, sourcePort, targetPort);
  if (portIssue) {
    return {
      actionId: targetId,
      ...portIssue,
    };
  }
  return null;
}

export function connectionClassForPorts(
  sourcePort?: WorkflowPortDefinition | null,
  targetPort?: WorkflowPortDefinition | null,
): WorkflowConnectionClass {
  return sourcePort?.connectionClass ?? targetPort?.connectionClass ?? "data";
}

export function validateWorkflowConnection(
  sourceKind: AgentActionKind,
  targetKind: AgentActionKind,
  sourcePort?: WorkflowPortDefinition | null,
  targetPort?: WorkflowPortDefinition | null,
): Pick<AgentActionValidationIssue, "code" | "message"> | null {
  if (!sourcePort || !targetPort) return null;
  if (sourcePort.direction !== "output") {
    return {
      code: "invalid_source_port",
      message: `${sourcePort.label} is not an output port.`,
    };
  }
  if (targetPort.direction !== "input") {
    return {
      code: "invalid_target_port",
      message: `${targetPort.label} is not an input port.`,
    };
  }
  if (sourcePort.connectionClass !== targetPort.connectionClass) {
    return {
      code: "invalid_connection_class",
      message: `${sourcePort.label} emits ${sourcePort.connectionClass}; ${targetPort.label} expects ${targetPort.connectionClass}.`,
    };
  }
  if (targetPort.connectableNodeKinds?.length) {
    const sourceNodeType = workflowNodeTypeForActionKind(sourceKind) as WorkflowNodeKind;
    if (!targetPort.connectableNodeKinds.includes(sourceNodeType)) {
      return {
        code: "invalid_source_node_kind",
        message: `${targetPort.label} cannot receive connections from ${sourceNodeType}.`,
      };
    }
  }
  if (sourcePort.connectableNodeKinds?.length) {
    const targetNodeType = workflowNodeTypeForActionKind(targetKind) as WorkflowNodeKind;
    if (!sourcePort.connectableNodeKinds.includes(targetNodeType)) {
      return {
        code: "invalid_target_node_kind",
        message: `${sourcePort.label} cannot connect to ${targetNodeType}.`,
      };
    }
  }
  return null;
}
