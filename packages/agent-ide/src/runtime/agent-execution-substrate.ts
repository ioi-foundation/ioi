import type {
  WorkflowConnectionClass,
  WorkflowNodeKind,
  WorkflowPortDefinition,
} from "../types/graph";

export type AgentExecutionSurface = "chat" | "workflow" | "harness" | "gui" | "unknown";

export type AgentActionKind =
  | "source_input"
  | "trigger"
  | "function"
  | "model_binding"
  | "model_call"
  | "parser"
  | "adapter_connector"
  | "plugin_tool"
  | "state"
  | "decision"
  | "loop"
  | "barrier"
  | "subgraph"
  | "human_gate"
  | "output"
  | "test_assertion"
  | "proposal"
  | "unknown";

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
    default:
      return kind;
  }
}

export function actionKindIsEntry(kind: AgentActionKind): boolean {
  return kind === "source_input" || kind === "trigger";
}

export function actionKindIsTerminal(kind: AgentActionKind): boolean {
  return kind === "output";
}

export function actionKindRequiresCompletionVerification(kind: AgentActionKind): boolean {
  return kind === "function" || kind === "model_binding" || kind === "model_call" || kind === "parser" || kind === "adapter_connector" || kind === "plugin_tool" || kind === "subgraph" || kind === "proposal";
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
