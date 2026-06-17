import type { NodeLogic, WorkflowNodeKind } from "../types/graph";
import { workflowNodeDefinition } from "./workflow-node-registry";
import {
  WORKFLOW_PRIMITIVE_CONFIG_SECTIONS,
  type WorkflowCanonicalPrimitive,
} from "./workflow-node-taxonomy";

export interface WorkflowPrimitiveConfigProjection {
  canonicalPrimitive: WorkflowCanonicalPrimitive;
  primitiveLabel: string;
  modeLabel: string;
  configSections: string[];
  authorityLabel: string;
  collapseTarget: string;
  rawNodeKind: WorkflowNodeKind;
  runtimeContract: string;
}

const PRIMITIVE_LABELS: Record<WorkflowCanonicalPrimitive, string> = {
  trigger: "Trigger",
  input: "Input",
  context: "Context",
  agent_step: "Agent Step",
  tool_pack: "Tool Pack",
  connector: "Connector",
  memory: "Memory",
  skills: "Skills",
  hook: "Hook",
  policy_gate: "Policy Gate",
  worker: "Worker",
  state: "State",
  control_flow: "Control Flow",
  verification: "Verification",
  recovery: "Recovery",
  pull_request: "Pull Request",
  output: "Output",
  harness_runtime: "Harness / Runtime",
};

function stateOperationMode(logic: NodeLogic): string | null {
  const operation = String(logic.stateOperation ?? "");
  if (operation.startsWith("memory_")) {
    return `Memory ${operation.replace("memory_", "").replace(/_/g, " ")}`;
  }
  if (operation.startsWith("subagent_")) {
    return `Worker ${operation.replace("subagent_", "").replace(/_/g, " ")}`;
  }
  if (operation.startsWith("mcp_tool_")) {
    return `MCP tool ${operation.replace("mcp_tool_", "").replace(/_/g, " ")}`;
  }
  if (operation.startsWith("mcp_")) {
    return `MCP ${operation.replace("mcp_", "").replace(/_/g, " ")}`;
  }
  return operation ? operation.replace(/_/g, " ") : null;
}

function modeLabel(kind: WorkflowNodeKind, logic: NodeLogic): string {
  if (kind === "skill_context") {
    return `Skill ${String(logic.skillContext?.mode ?? "discover")}`;
  }
  if (kind === "skill_pack") return "Skill pack";
  if (kind === "skill") return "Single skill";
  if (kind === "model_call") {
    return String(logic.modelBinding?.toolUseMode ?? logic.toolUseMode ?? "reasoning");
  }
  if (kind === "model_binding") return "Model route";
  if (kind === "parser") return "Structured output";
  if (kind === "plugin_tool") {
    const bindingKind = String(logic.toolBinding?.bindingKind ?? "tool");
    const pack = logic.toolBinding?.toolPack?.pack
      ? ` ${String(logic.toolBinding.toolPack.pack)}`
      : "";
    return `${bindingKind.replace(/_/g, " ")}${pack}`.trim();
  }
  if (kind === "state") return stateOperationMode(logic) ?? "State operation";
  if (kind === "repository_context") return "Repository context";
  if (kind === "github_context") return "GitHub context";
  if (kind === "issue_context") return "Issue context";
  if (kind === "branch_policy") return "Branch policy";
  if (kind === "pr_attempt") return "PR attempt";
  if (kind === "github_pr_create") return "Create pull request";
  if (kind === "review_gate") return "Review gate";
  if (kind === "hook_policy") return "Hook policy";
  if (kind === "hook") return "Event hook";
  return workflowNodeDefinition(kind).label;
}

function authorityLabel(logic: NodeLogic): string {
  const toolBinding = logic.toolBinding;
  const connectorBinding = logic.connectorBinding;
  if (toolBinding?.requiresApproval || connectorBinding?.requiresApproval) {
    return "approval required";
  }
  if (toolBinding?.sideEffectClass) {
    return String(toolBinding.sideEffectClass);
  }
  if (connectorBinding?.sideEffectClass) {
    return String(connectorBinding.sideEffectClass);
  }
  return "runtime policy";
}

function stateOperationPrimitive(
  operation: string,
): WorkflowCanonicalPrimitive | null {
  if (operation.startsWith("memory_")) return "memory";
  if (operation.startsWith("subagent_")) return "worker";
  if (operation === "mcp_tool_invoke") return "tool_pack";
  if (operation.startsWith("mcp_")) return "connector";
  return null;
}

export function workflowPrimitiveConfigProjection(
  kind: WorkflowNodeKind,
  logic: NodeLogic = {},
): WorkflowPrimitiveConfigProjection {
  const definition = workflowNodeDefinition(kind);
  const canonicalPrimitive =
    kind === "state"
      ? (stateOperationPrimitive(String(logic.stateOperation ?? "")) ??
        definition.canonicalPrimitive)
      : definition.canonicalPrimitive;
  return {
    canonicalPrimitive,
    primitiveLabel: PRIMITIVE_LABELS[canonicalPrimitive],
    modeLabel: modeLabel(kind, logic),
    configSections: WORKFLOW_PRIMITIVE_CONFIG_SECTIONS[canonicalPrimitive],
    authorityLabel: authorityLabel(logic),
    collapseTarget:
      canonicalPrimitive === definition.canonicalPrimitive
        ? definition.collapseTarget
        : `${canonicalPrimitive}.${String(logic.stateOperation ?? "operation")}`,
    rawNodeKind: kind,
    runtimeContract: definition.runtimeMapping.contract,
  };
}
