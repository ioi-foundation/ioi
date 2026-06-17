import type {
  Edge as ReactFlowEdge,
  Node as ReactFlowNode,
} from "@xyflow/react";

import type { Edge, Node } from "../types/graph";

export interface WorkflowRuntimeSubflowForInsertion {
  nodes: Node[];
  edges: Edge[];
}

export function workflowRuntimeSubflowReactFlowElements(
  subflow: WorkflowRuntimeSubflowForInsertion,
): { nodes: ReactFlowNode[]; edges: ReactFlowEdge[] } {
  return {
    nodes: subflow.nodes.map(
      (node): ReactFlowNode => ({
        id: node.id,
        type: node.type,
        position: { x: node.x, y: node.y },
        data: { ...node },
      }),
    ),
    edges: subflow.edges.map(
      (edge): ReactFlowEdge => ({
        id: edge.id,
        source: edge.from,
        target: edge.to,
        sourceHandle: edge.fromPort,
        targetHandle: edge.toPort,
        type: "semantic",
        animated: false,
        data: {
          ...(edge.data ?? {}),
          connectionClass: edge.connectionClass ?? edge.type,
        },
      }),
    ),
  };
}
