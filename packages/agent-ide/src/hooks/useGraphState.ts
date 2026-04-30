// packages/agent-ide/src/hooks/useGraphState.ts
import { useState, useCallback } from "react";
import { 
  useNodesState, 
  useEdgesState, 
  addEdge, 
  Connection, 
  useReactFlow,
  Node as FlowNode,
  Edge as FlowEdge
} from "@xyflow/react";
import { Node, Edge, NodeLogic, FirewallPolicy, ProjectFile } from "../types/graph";
import {
  actionKindForWorkflowNodeType,
  connectionClassForPorts,
  validateActionEdge,
} from "../runtime/agent-execution-substrate";
import {
  workflowNodeDefaultLaw,
  workflowNodeDefaultLogic,
  workflowNodeDefaults,
} from "../runtime/workflow-node-registry";

function toFlowNodes(nodes: Node[]): FlowNode[] {
  return nodes.map((node) => ({
    id: node.id,
    type: node.type,
    position: { x: node.x, y: node.y },
    data: { ...node },
  }));
}

function toFlowEdges(edges: Edge[]): FlowEdge[] {
  return edges.map((edge) => ({
    id: edge.id,
    source: edge.from,
    target: edge.to,
    sourceHandle: edge.fromPort,
    targetHandle: edge.toPort,
    type: "semantic",
    animated: false,
    data: { ...(edge.data ?? {}), connectionClass: edge.connectionClass ?? edge.data?.connectionClass ?? edge.type },
  }));
}

function flowNodeType(node: FlowNode | undefined): string {
  if (!node) return "";
  return String(node.type ?? (node.data as Node | undefined)?.type ?? "");
}

function flowNodePort(node: FlowNode | undefined, handleId: string | null | undefined, direction: "input" | "output") {
  const data = node?.data as Node | undefined;
  return data?.ports?.find((port) => port.id === (handleId || (direction === "output" ? "output" : "input")) && port.direction === direction);
}

export function useGraphState(initialNodes: Node[] = [], initialEdges: Edge[] = []) {
  const flowNodes = toFlowNodes(initialNodes);
  const flowEdges = toFlowEdges(initialEdges);

  const [nodes, setNodes, onNodesChange] = useNodesState<FlowNode>(flowNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState<FlowEdge>(flowEdges);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  
  const { screenToFlowPosition, fitView, zoomIn, zoomOut } = useReactFlow();

  const onConnect = useCallback(
    (params: Connection) => {
      const sourceType = flowNodeType(nodes.find((node) => node.id === params.source));
      const sourceNode = nodes.find((node) => node.id === params.source);
      const targetNode = nodes.find((node) => node.id === params.target);
      const targetType = flowNodeType(targetNode);
      const sourcePort = flowNodePort(sourceNode, params.sourceHandle, "output");
      const targetPort = flowNodePort(targetNode, params.targetHandle, "input");
      if (validateActionEdge(
        params.source ?? "",
        actionKindForWorkflowNodeType(sourceType),
        params.target ?? "",
        actionKindForWorkflowNodeType(targetType),
        sourcePort,
        targetPort,
      )) return;
      const connectionClass = connectionClassForPorts(sourcePort, targetPort);
      setEdges((eds) => addEdge({
        ...params,
        type: 'semantic',
        animated: false,
        data: { status: 'idle', active: false, connectionClass }
      }, eds));
    },
    [nodes, setEdges],
  );

  const handleNodeSelect = useCallback((nodeId: string | null) => {
    setSelectedNodeId(nodeId);
  }, []);

  const handleNodeUpdate = useCallback((nodeId: string, section: 'logic' | 'law', updates: Partial<NodeLogic> | Partial<FirewallPolicy>) => {
    setNodes((nds) => nds.map((node) => {
      if (node.id === nodeId) {
        const currentData = node.data as unknown as Node;
        const currentConfig = currentData.config || { kind: String(currentData.type || "function") as any, logic: {}, law: {} };
        const nextConfig =
          section === "logic"
            ? {
                ...currentConfig,
                logic: { ...currentConfig.logic, ...(updates as Partial<NodeLogic>) },
              }
            : {
                ...currentConfig,
                law: { ...currentConfig.law, ...(updates as Partial<FirewallPolicy>) },
              };

        return {
          ...node,
          data: {
            ...node.data,
            config: nextConfig,
          },
        };
      }
      return node;
    }));
  }, [setNodes]);

  const handleCanvasDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    const type = e.dataTransfer.getData("nodeType");
    const name = e.dataTransfer.getData("nodeName");
    const schema = e.dataTransfer.getData("nodeSchema");
    const pos = screenToFlowPosition({ x: e.clientX, y: e.clientY });
    const nodeType = type || "action";
    const defaults = workflowNodeDefaults(nodeType);
    const nodeId = `node-${Date.now()}`;
    const newNode: FlowNode = {
        id: nodeId,
        type: nodeType,
        position: pos,
        data: {
            id: nodeId,
            type: nodeType,
            name: name || "New Node",
            x: pos.x,
            y: pos.y,
            schema: schema || undefined,
            ...defaults,
            config: { kind: nodeType as any, logic: workflowNodeDefaultLogic(nodeType), law: workflowNodeDefaultLaw(nodeType) }
        }
    };
    setNodes(prev => [...prev, newNode]);
    setSelectedNodeId(nodeId);
  }, [screenToFlowPosition, setNodes]);

  const addNode = useCallback((type: string, name: string, preferredId?: string): string => {
    const nodeType = type || "source";
    const defaults = workflowNodeDefaults(nodeType);
    const nodeId = preferredId || `node-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    setNodes((currentNodes) => {
      const column = currentNodes.length % 5;
      const row = Math.floor(currentNodes.length / 5);
      const position = {
        x: 120 + column * 260,
        y: 160 + row * 150,
      };
      return [
        ...currentNodes,
        {
          id: nodeId,
          type: nodeType,
          position,
          data: {
            id: nodeId,
            type: nodeType,
            name: name || "New node",
            x: position.x,
            y: position.y,
            ...defaults,
            config: { kind: nodeType as any, logic: workflowNodeDefaultLogic(nodeType), law: workflowNodeDefaultLaw(nodeType) },
          },
        },
      ];
    });
    setSelectedNodeId(nodeId);
    return nodeId;
  }, [setNodes]);

  const replaceGraph = useCallback((project: ProjectFile) => {
    setNodes(toFlowNodes(project.nodes ?? []));
    setEdges(toFlowEdges(project.edges ?? []));
    setSelectedNodeId(null);
  }, [setEdges, setNodes]);

  return {
    nodes, edges, setNodes, setEdges, onNodesChange, onEdgesChange,
    onConnect, selectedNodeId, handleNodeSelect, handleNodeUpdate, handleCanvasDrop,
    fitView, zoomIn, zoomOut, replaceGraph, addNode
  };
}
