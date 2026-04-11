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
    data: { ...(edge.data ?? {}) },
  }));
}

export function useGraphState(initialNodes: Node[] = [], initialEdges: Edge[] = []) {
  const flowNodes = toFlowNodes(initialNodes);
  const flowEdges = toFlowEdges(initialEdges);

  const [nodes, setNodes, onNodesChange] = useNodesState<FlowNode>(flowNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState<FlowEdge>(flowEdges);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  
  const { screenToFlowPosition, fitView, zoomIn, zoomOut } = useReactFlow();

  const onConnect = useCallback(
    (params: Connection) => setEdges((eds) => addEdge({ 
      ...params, 
      type: 'semantic', 
      animated: false,
      data: { status: 'idle', active: false } 
    }, eds)),
    [setEdges],
  );

  const handleNodeSelect = useCallback((nodeId: string | null) => {
    setSelectedNodeId(nodeId);
  }, []);

  const handleNodeUpdate = useCallback((nodeId: string, section: 'logic' | 'law', updates: Partial<NodeLogic> | Partial<FirewallPolicy>) => {
    setNodes((nds) => nds.map((node) => {
      if (node.id === nodeId) {
        const currentData = node.data as unknown as Node;
        const currentConfig = currentData.config || { logic: {}, law: {} };
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
    const nodeId = `node-${Date.now()}`;
    
    const newNode: FlowNode = {
        id: nodeId,
        type: type || 'action',
        position: pos,
        data: { 
            id: nodeId, 
            type: type || 'action', 
            name: name || "New Node",
            schema: schema || undefined,
            config: { logic: {}, law: {} }
        }
    };
    setNodes(prev => [...prev, newNode]);
  }, [screenToFlowPosition, setNodes]);

  const replaceGraph = useCallback((project: ProjectFile) => {
    setNodes(toFlowNodes(project.nodes ?? []));
    setEdges(toFlowEdges(project.edges ?? []));
    setSelectedNodeId(null);
  }, [setEdges, setNodes]);

  return {
    nodes, edges, setNodes, setEdges, onNodesChange, onEdgesChange,
    onConnect, selectedNodeId, handleNodeSelect, handleNodeUpdate, handleCanvasDrop,
    fitView, zoomIn, zoomOut, replaceGraph
  };
}
